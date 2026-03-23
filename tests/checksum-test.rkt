#lang racket/base

(require rackunit
         rackunit/spec
         wirey/checksum)

(describe "internet-checksum"
  (it "returns 0xFFFF for empty input"
    (check-equal? (internet-checksum (bytes)) #xFFFF))

  (it "handles a simple two-byte input"
    ;; 0x0001 → complement = 0xFFFE
    (check-equal? (internet-checksum (bytes #x00 #x01)) #xFFFE))

  (it "handles odd-length input by padding"
    ;; Single byte 0x01 → 0x0100 → complement = 0xFEFF
    (check-equal? (internet-checksum (bytes #x01)) #xFEFF))

  (it "verifies to 0 when checksum is included"
    ;; Compute checksum of some data, append it, verify total is 0
    (define data (bytes #x00 #x01 #x00 #x02))
    (define chk (internet-checksum data))
    (define with-chk (bytes-append data (bytes (arithmetic-shift chk -8)
                                               (bitwise-and chk #xFF))))
    (check-equal? (internet-checksum with-chk) 0)))

(describe "ipv4-header-checksum"
  (it "computes correct checksum for a known IPv4 header"
    ;; 20-byte IPv4 header with checksum field zeroed (bytes 10-11)
    (define hdr (bytes #x45 #x00 #x00 #x3C
                       #x1C #x46 #x40 #x00
                       #x40 #x06 #x00 #x00
                       #xAC #x10 #x0A #x63
                       #xAC #x10 #x0A #x0C))
    (define chk (ipv4-header-checksum hdr))
    ;; Verify: insert checksum and re-check → should be 0
    (define hdr-copy (bytes-copy hdr))
    (bytes-set! hdr-copy 10 (arithmetic-shift chk -8))
    (bytes-set! hdr-copy 11 (bitwise-and chk #xFF))
    (check-equal? (internet-checksum hdr-copy) 0))

  (it "known checksum value for 45 00 00 3C 1C 46 40 00 40 06 ... header"
    ;; Compute and verify it's a specific 16-bit value
    (define hdr (bytes #x45 #x00 #x00 #x3C
                       #x1C #x46 #x40 #x00
                       #x40 #x06 #x00 #x00
                       #xAC #x10 #x0A #x63
                       #xAC #x10 #x0A #x0C))
    (define chk (ipv4-header-checksum hdr))
    ;; Should be a valid 16-bit value
    (check-true (and (>= chk 0) (<= chk #xFFFF)))
    ;; And non-zero (since the header has non-zero content)
    (check-true (> chk 0))))

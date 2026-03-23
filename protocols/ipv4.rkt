#lang racket/base

(require wirey/syntax)

(provide (all-defined-out))

;; ============================================================
;; IPv4 Header — fixed 20-byte portion
;; Variable-length options (when IHL > 5) deferred to v0.3.
;; All multi-byte fields are big-endian (network byte order).
;; ============================================================

(struct/wire ipv4-header
  #:byte-order big
  (version          uint 4  #:unit bits)
  (ihl              uint 4  #:unit bits)
  (dscp             uint 6  #:unit bits)
  (ecn              uint 2  #:unit bits)
  (total-length     uint 2)
  (identification   uint 2)
  (flags            uint 3  #:unit bits)
  (fragment-offset  uint 13 #:unit bits)
  (ttl              uint 1)
  (protocol         uint 1)
  (header-checksum  uint 2)
  (src-ip           uint 4)
  (dst-ip           uint 4))

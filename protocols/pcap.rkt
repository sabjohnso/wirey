#lang racket/base

(require wirey/syntax)

(provide (all-defined-out))

;; ============================================================
;; PCAP File Format Headers
;; Byte order is typically little-endian (for native captures).
;; The magic number determines actual byte order at runtime;
;; these definitions use little-endian as the common case.
;; ============================================================

;; Global Header — 24 bytes
(define-protocol pcap-global-header
  #:byte-order little
  (magic-number   uint   4)
  (version-major  uint   2)
  (version-minor  uint   2)
  (thiszone       sint   4)
  (sigfigs        uint   4)
  (snaplen        uint   4)
  (network        uint   4))

;; Packet Record Header — 16 bytes
(define-protocol pcap-record-header
  #:byte-order little
  (ts-sec    uint 4)
  (ts-usec   uint 4)
  (incl-len  uint 4)
  (orig-len  uint 4))

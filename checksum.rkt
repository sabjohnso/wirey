#lang racket/base

(provide internet-checksum
         ipv4-header-checksum)

;; ============================================================
;; Internet Checksum (RFC 1071)
;; One's complement sum of 16-bit words, then one's complement.
;; ============================================================

(define (internet-checksum data)
  (define len (bytes-length data))
  (define sum
    (let loop ([i 0] [acc 0])
      (cond
        [(>= i (sub1 len))
         ;; Handle odd byte by padding with zero
         (if (= i (sub1 len))
             (+ acc (arithmetic-shift (bytes-ref data i) 8))
             acc)]
        [else
         (define word (bitwise-ior
                       (arithmetic-shift (bytes-ref data i) 8)
                       (bytes-ref data (+ i 1))))
         (loop (+ i 2) (+ acc word))])))
  ;; Fold 32-bit carry into 16 bits
  (define folded
    (let loop ([s sum])
      (if (> s #xFFFF)
          (loop (+ (bitwise-and s #xFFFF) (arithmetic-shift s -16)))
          s)))
  ;; One's complement
  (bitwise-and (bitwise-not folded) #xFFFF))

;; ============================================================
;; IPv4 Header Checksum
;; Assumes the checksum field (bytes 10-11) is zeroed in the input.
;; ============================================================

(define (ipv4-header-checksum header-bytes)
  (internet-checksum header-bytes))

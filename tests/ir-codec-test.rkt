#lang racket/base

(require rackunit
         rackunit/spec
         wirey/ir
         wirey/ir-codec)

;; -- helpers --
(define (hex->bytes str)
  (define clean (regexp-replace* #rx" " str ""))
  (apply bytes
         (for/list ([i (in-range 0 (string-length clean) 2)])
           (string->number (substring clean i (+ i 2)) 16))))

;; ============================================================
;; Basic field encode/decode
;; ============================================================

(define simple-protocol
  (wire-protocol 'simple
    (list (wire-field 'tag 'uint (width-fixed 1) 'big (hasheq))
          (wire-field 'val 'uint (width-fixed 2) 'big (hasheq)))
    (hasheq)))

(describe "ir-codec: simple fields"
  (it "encodes uint fields"
    (define bs (ir-encode simple-protocol (hasheq 'tag #xAA 'val #x1234)))
    (check-equal? bs (bytes #xAA #x12 #x34)))

  (it "decodes uint fields"
    (define h (ir-decode simple-protocol (bytes #xAA #x12 #x34)))
    (check-equal? (hash-ref h 'tag) #xAA)
    (check-equal? (hash-ref h 'val) #x1234))

  (it "round-trips"
    (define v (hasheq 'tag #xBB 'val #x5678))
    (check-equal? (ir-decode simple-protocol (ir-encode simple-protocol v)) v)))

;; ============================================================
;; Bitfield groups
;; ============================================================

(define bitfield-protocol
  (wire-protocol 'ipv4-start
    (list (wire-bitfield-group
            (list (wire-bit-field 'version 'uint 4 (hasheq))
                  (wire-bit-field 'ihl     'uint 4 (hasheq)))
            'msb 8)
          (wire-field 'total-length 'uint (width-fixed 2) 'big (hasheq)))
    (hasheq)))

(describe "ir-codec: bitfield groups"
  (it "encodes MSB bitfields"
    (define bs (ir-encode bitfield-protocol (hasheq 'version 4 'ihl 5 'total-length 1500)))
    (check-equal? (bytes-ref bs 0) #x45)
    (check-equal? bs (bytes #x45 #x05 #xDC)))

  (it "decodes MSB bitfields"
    (define h (ir-decode bitfield-protocol (bytes #x45 #x05 #xDC)))
    (check-equal? (hash-ref h 'version) 4)
    (check-equal? (hash-ref h 'ihl) 5)
    (check-equal? (hash-ref h 'total-length) 1500))

  (it "round-trips"
    (define v (hasheq 'version 4 'ihl 5 'total-length 1500))
    (check-equal? (ir-decode bitfield-protocol (ir-encode bitfield-protocol v)) v)))

;; ============================================================
;; Case dispatch
;; ============================================================

(define case-protocol
  (wire-protocol 'tagged-msg
    (list (wire-field 'tag 'uint (width-fixed 1) 'big (hasheq))
          (wire-case 'tag
            (list (wire-case-branch 1
                    (list (wire-field 'val 'uint (width-fixed 1) 'big (hasheq))))
                  (wire-case-branch 2
                    (list (wire-field 'val 'uint (width-fixed 2) 'big (hasheq)))))))
    (hasheq)))

(describe "ir-codec: case dispatch"
  (it "encodes branch 1"
    (check-equal? (ir-encode case-protocol (hasheq 'tag 1 'val #xAA))
                  (bytes 1 #xAA)))

  (it "encodes branch 2"
    (check-equal? (ir-encode case-protocol (hasheq 'tag 2 'val #xBBCC))
                  (bytes 2 #xBB #xCC)))

  (it "decodes branch 1"
    (define h (ir-decode case-protocol (bytes 1 #xAA)))
    (check-equal? (hash-ref h 'tag) 1)
    (check-equal? (hash-ref h 'val) #xAA))

  (it "decodes branch 2"
    (define h (ir-decode case-protocol (bytes 2 #xBB #xCC)))
    (check-equal? (hash-ref h 'val) #xBBCC))

  (it "inactive branch fields are #f"
    (define h (ir-decode case-protocol (bytes 1 #xAA)))
    ;; val exists (from branch 1), but a field from branch 2 would be #f
    (check-equal? (hash-ref h 'val) #xAA)))

;; ============================================================
;; Variable-length fields
;; ============================================================

(define varlen-protocol
  (wire-protocol 'length-prefixed
    (list (wire-field 'len  'uint   (width-fixed 2) 'big (hasheq))
          (wire-field 'data 'octets (width-field-ref 'len) 'big (hasheq)))
    (hasheq)))

(describe "ir-codec: variable-length fields"
  (it "encodes"
    (define bs (ir-encode varlen-protocol (hasheq 'len 3 'data (bytes 1 2 3))))
    (check-equal? bs (bytes 0 3 1 2 3)))

  (it "decodes"
    (define h (ir-decode varlen-protocol (bytes 0 3 1 2 3)))
    (check-equal? (hash-ref h 'len) 3)
    (check-equal? (hash-ref h 'data) (bytes 1 2 3)))

  (it "round-trips"
    (define v (hasheq 'len 4 'data (bytes 10 20 30 40)))
    (check-equal? (ir-decode varlen-protocol (ir-encode varlen-protocol v)) v)))

;; ============================================================
;; Padding
;; ============================================================

(define padded-protocol
  (wire-protocol 'padded
    (list (wire-field   'tag 'uint (width-fixed 1) 'big (hasheq))
          (wire-padding (width-fixed 3))
          (wire-field   'val 'uint (width-fixed 4) 'big (hasheq)))
    (hasheq)))

(describe "ir-codec: padding"
  (it "encodes with zero padding"
    (define bs (ir-encode padded-protocol (hasheq 'tag #xAA 'val #xDEADBEEF)))
    (check-equal? bs (bytes #xAA 0 0 0 #xDE #xAD #xBE #xEF)))

  (it "decodes skipping padding"
    (define h (ir-decode padded-protocol (bytes #xAA 0 0 0 #xDE #xAD #xBE #xEF)))
    (check-equal? (hash-ref h 'tag) #xAA)
    (check-equal? (hash-ref h 'val) #xDEADBEEF)
    (check-false (hash-has-key? h '__pad))))

;; ============================================================
;; Case with variable-length (CBOR-like pattern)
;; ============================================================

(define cbor-like-protocol
  (wire-protocol 'cbor-like
    (list (wire-field 'info 'uint (width-fixed 1) 'big (hasheq))
          (wire-case 'info
            (list (wire-case-branch (λ (v) (<= v 23)) '())
                  (wire-case-branch 24
                    (list (wire-field 'argument 'uint (width-fixed 1) 'big (hasheq))))
                  (wire-case-branch 25
                    (list (wire-field 'argument 'uint (width-fixed 2) 'big (hasheq))))))
          (wire-field 'payload 'octets
            (width-compute (λ (lk) (or (lk 'argument) (lk 'info))))
            'big (hasheq)))
    (hasheq)))

(describe "ir-codec: CBOR-like cross-case pattern"
  (it "decodes inline value (info <= 23)"
    (define h (ir-decode cbor-like-protocol (bytes 5 10 20 30 40 50)))
    (check-equal? (hash-ref h 'info) 5)
    (check-equal? (hash-ref h 'payload) (bytes 10 20 30 40 50)))

  (it "decodes 1-byte argument"
    (define h (ir-decode cbor-like-protocol (bytes 24 3 10 20 30)))
    (check-equal? (hash-ref h 'argument) 3)
    (check-equal? (hash-ref h 'payload) (bytes 10 20 30)))

  (it "round-trips with 2-byte argument"
    (define v (hasheq 'info 25 'argument 4 'payload (bytes 1 2 3 4)))
    (check-equal? (ir-decode cbor-like-protocol
                    (ir-encode cbor-like-protocol v)) v)))

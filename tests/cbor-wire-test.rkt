#lang racket/base

(require rackunit
         rackunit/spec
         racket/list
         wirey/protocols/cbor-wire)

;; Helper
(define (hex->bytes str)
  (define clean (regexp-replace* #rx" " str ""))
  (apply bytes
         (for/list ([i (in-range 0 (string-length clean) 2)])
           (string->number (substring clean i (+ i 2)) 16))))

;; Helper: get effective argument
(define (cbor-argument v)
  (or (cbor-wire-item-ext-arg v)
      (cbor-wire-item-additional-info v)))

;; ============================================================
;; CBOR struct/wire decode tests — RFC 8949 vectors
;; ============================================================

(describe "CBOR wire: unsigned integers (MT 0)"
  (it "0"   (check-equal? (cbor-argument (cbor-wire-item-decode (bytes #x00))) 0))
  (it "1"   (check-equal? (cbor-argument (cbor-wire-item-decode (bytes #x01))) 1))
  (it "10"  (check-equal? (cbor-argument (cbor-wire-item-decode (bytes #x0A))) 10))
  (it "23"  (check-equal? (cbor-argument (cbor-wire-item-decode (bytes #x17))) 23))
  (it "24"  (check-equal? (cbor-argument (cbor-wire-item-decode (bytes #x18 #x18))) 24))
  (it "100" (check-equal? (cbor-argument (cbor-wire-item-decode (bytes #x18 #x64))) 100))
  (it "1000" (check-equal? (cbor-argument (cbor-wire-item-decode (bytes #x19 #x03 #xE8))) 1000))
  (it "1000000"
    (check-equal? (cbor-argument (cbor-wire-item-decode (hex->bytes "1A 00 0F 42 40"))) 1000000)))

(describe "CBOR wire: negative integers (MT 1)"
  (it "-1 (arg=0)"
    (define v (cbor-wire-item-decode (bytes #x20)))
    (check-equal? (cbor-wire-item-major-type v) 1)
    (check-equal? (cbor-argument v) 0))
  (it "-100 (arg=99)"
    (define v (cbor-wire-item-decode (bytes #x38 #x63)))
    (check-equal? (cbor-argument v) 99)))

(describe "CBOR wire: byte strings (MT 2)"
  (it "empty"
    (define v (cbor-wire-item-decode (bytes #x40)))
    (check-equal? (cbor-wire-item-major-type v) 2)
    (check-equal? (cbor-wire-item-payload v) (bytes)))
  (it "h'01020304'"
    (define v (cbor-wire-item-decode (bytes #x44 #x01 #x02 #x03 #x04)))
    (check-equal? (cbor-wire-item-payload v) (bytes 1 2 3 4))))

(describe "CBOR wire: text strings (MT 3)"
  (it "empty"
    (define v (cbor-wire-item-decode (bytes #x60)))
    (check-equal? (cbor-wire-item-payload v) (bytes)))
  (it "\"IETF\""
    (define v (cbor-wire-item-decode (bytes #x64 #x49 #x45 #x54 #x46)))
    (check-equal? (cbor-wire-item-payload v) #"IETF")))

(describe "CBOR wire: arrays (MT 4)"
  (it "empty"
    (define v (cbor-wire-item-decode (bytes #x80)))
    (check-equal? (cbor-wire-item-items v) '()))
  (it "[1, 2, 3]"
    (define v (cbor-wire-item-decode (bytes #x83 #x01 #x02 #x03)))
    (define items (cbor-wire-item-items v))
    (check-equal? (length items) 3)
    (check-equal? (cbor-argument (first items)) 1)
    (check-equal? (cbor-argument (second items)) 2)
    (check-equal? (cbor-argument (third items)) 3))
  (it "nested [[1], [2, 3]]"
    (define v (cbor-wire-item-decode (hex->bytes "82 81 01 82 02 03")))
    (define items (cbor-wire-item-items v))
    (check-equal? (length items) 2)
    (check-equal? (length (cbor-wire-item-items (first items))) 1)
    (check-equal? (length (cbor-wire-item-items (second items))) 2)))

(describe "CBOR wire: maps (MT 5)"
  (it "empty"
    (define v (cbor-wire-item-decode (bytes #xA0)))
    (check-equal? (cbor-wire-item-pairs v) '()))
  (it "{1: 2, 3: 4}"
    (define v (cbor-wire-item-decode (hex->bytes "A2 01 02 03 04")))
    (define pairs (cbor-wire-item-pairs v))
    ;; 2 pairs = 4 items (k1 v1 k2 v2)
    (check-equal? (length pairs) 4)
    (check-equal? (cbor-argument (first pairs)) 1)
    (check-equal? (cbor-argument (second pairs)) 2)))

(describe "CBOR wire: tags (MT 6)"
  (it "tag 1"
    (define v (cbor-wire-item-decode (hex->bytes "C1 1A 51 4B 67 B0")))
    (check-equal? (cbor-wire-item-major-type v) 6)
    (check-equal? (cbor-argument v) 1)
    (define tagged (cbor-wire-item-tagged v))
    (check-pred cbor-wire-item? tagged)
    (check-equal? (cbor-wire-item-major-type tagged) 0)
    (check-equal? (cbor-argument tagged) #x514B67B0)))

(describe "CBOR wire: simple values (MT 7)"
  (it "false"
    (define v (cbor-wire-item-decode (bytes #xF4)))
    (check-equal? (cbor-wire-item-major-type v) 7)
    (check-equal? (cbor-wire-item-additional-info v) 20))
  (it "true"
    (check-equal? (cbor-wire-item-additional-info
                   (cbor-wire-item-decode (bytes #xF5))) 21))
  (it "null"
    (check-equal? (cbor-wire-item-additional-info
                   (cbor-wire-item-decode (bytes #xF6))) 22)))

(describe "CBOR wire: complex nested"
  (it "{\"a\": 1, \"b\": [2, 3]}"
    (define v (cbor-wire-item-decode (hex->bytes "A2 61 61 01 61 62 82 02 03")))
    (check-equal? (cbor-wire-item-major-type v) 5)
    ;; 2 pairs = 4 items
    (define pairs (cbor-wire-item-pairs v))
    (check-equal? (length pairs) 4)
    ;; First key: "a" (text, 1 byte)
    (check-equal? (cbor-wire-item-major-type (first pairs)) 3)
    ;; First value: 1
    (check-equal? (cbor-argument (second pairs)) 1)
    ;; Second key: "b"
    (check-equal? (cbor-wire-item-major-type (third pairs)) 3)
    ;; Second value: [2, 3]
    (define arr (fourth pairs))
    (check-equal? (cbor-wire-item-major-type arr) 4)
    (check-equal? (length (cbor-wire-item-items arr)) 2)))

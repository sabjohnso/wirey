#lang racket/base

(require rackunit
         rackunit/spec
         racket/list
         wirey/protocols/cbor)

;; Helper
(define (hex->bytes str)
  (define clean (regexp-replace* #rx" " str ""))
  (apply bytes
         (for/list ([i (in-range 0 (string-length clean) 2)])
           (string->number (substring clean i (+ i 2)) 16))))

;; ===== RFC 8949 Appendix A Test Vectors =====

(describe "CBOR unsigned integers (major 0)"
  (it "decodes 0"
    (check-equal? (cbor-decode (bytes #x00)) (cbor-unsigned 0)))
  (it "decodes 1"
    (check-equal? (cbor-decode (bytes #x01)) (cbor-unsigned 1)))
  (it "decodes 10"
    (check-equal? (cbor-decode (bytes #x0A)) (cbor-unsigned 10)))
  (it "decodes 23"
    (check-equal? (cbor-decode (bytes #x17)) (cbor-unsigned 23)))
  (it "decodes 24 (1-byte)"
    (check-equal? (cbor-decode (bytes #x18 #x18)) (cbor-unsigned 24)))
  (it "decodes 25 (1-byte)"
    (check-equal? (cbor-decode (bytes #x18 #x19)) (cbor-unsigned 25)))
  (it "decodes 100 (1-byte)"
    (check-equal? (cbor-decode (bytes #x18 #x64)) (cbor-unsigned 100)))
  (it "decodes 1000 (2-byte)"
    (check-equal? (cbor-decode (bytes #x19 #x03 #xE8)) (cbor-unsigned 1000)))
  (it "decodes 1000000 (4-byte)"
    (check-equal? (cbor-decode (hex->bytes "1A 00 0F 42 40")) (cbor-unsigned 1000000)))
  (it "decodes 1000000000000 (8-byte)"
    (check-equal? (cbor-decode (hex->bytes "1B 00 00 00 E8 D4 A5 10 00"))
                  (cbor-unsigned 1000000000000))))

(describe "CBOR negative integers (major 1)"
  (it "decodes -1"
    (check-equal? (cbor-decode (bytes #x20)) (cbor-negative 0)))
  (it "decodes -10"
    (check-equal? (cbor-decode (bytes #x29)) (cbor-negative 9)))
  (it "decodes -100"
    (check-equal? (cbor-decode (bytes #x38 #x63)) (cbor-negative 99)))
  (it "decodes -1000"
    (check-equal? (cbor-decode (bytes #x39 #x03 #xE7)) (cbor-negative 999))))

(describe "CBOR byte strings (major 2)"
  (it "decodes empty byte string"
    (check-equal? (cbor-decode (bytes #x40)) (cbor-bytes (bytes))))
  (it "decodes 4-byte string"
    (check-equal? (cbor-decode (bytes #x44 #x01 #x02 #x03 #x04))
                  (cbor-bytes (bytes 1 2 3 4)))))

(describe "CBOR text strings (major 3)"
  (it "decodes empty text"
    (check-equal? (cbor-decode (bytes #x60)) (cbor-text "")))
  (it "decodes 'a'"
    (check-equal? (cbor-decode (bytes #x61 #x61)) (cbor-text "a")))
  (it "decodes 'IETF'"
    (check-equal? (cbor-decode (bytes #x64 #x49 #x45 #x54 #x46)) (cbor-text "IETF")))
  (it "decodes '\"\\'"
    (check-equal? (cbor-decode (bytes #x62 #x22 #x5C)) (cbor-text "\"\\")))
  (it "decodes unicode"
    (check-equal? (cbor-decode (bytes #x62 #xC3 #xBC)) (cbor-text "\u00fc"))))

(describe "CBOR arrays (major 4)"
  (it "decodes empty array"
    (check-equal? (cbor-decode (bytes #x80)) (cbor-array '())))
  (it "decodes [1, 2, 3]"
    (check-equal? (cbor-decode (bytes #x83 #x01 #x02 #x03))
                  (cbor-array (list (cbor-unsigned 1) (cbor-unsigned 2) (cbor-unsigned 3)))))
  (it "decodes nested [[1], [2, 3], [4, 5]]"
    (define result (cbor-decode (hex->bytes "83 81 01 82 02 03 82 04 05")))
    (check-pred cbor-array? result)
    (check-equal? (length (cbor-array-items result)) 3)
    (define inner1 (first (cbor-array-items result)))
    (check-equal? inner1 (cbor-array (list (cbor-unsigned 1))))))

(describe "CBOR maps (major 5)"
  (it "decodes empty map"
    (check-equal? (cbor-decode (bytes #xA0)) (cbor-map '())))
  (it "decodes {1: 2, 3: 4}"
    (define result (cbor-decode (hex->bytes "A2 01 02 03 04")))
    (check-pred cbor-map? result)
    (define entries (cbor-map-entries result))
    (check-equal? (length entries) 2)
    (check-equal? (car (first entries)) (cbor-unsigned 1))
    (check-equal? (cdr (first entries)) (cbor-unsigned 2))))

(describe "CBOR tags (major 6)"
  (it "decodes tag 1 (epoch time)"
    (define result (cbor-decode (hex->bytes "C1 1A 51 4B 67 B0")))
    (check-pred cbor-tag? result)
    (check-equal? (cbor-tag-number result) 1)
    (check-equal? (cbor-tag-content result) (cbor-unsigned #x514B67B0))))

(describe "CBOR simple values and floats (major 7)"
  (it "decodes false"
    (check-equal? (cbor-decode (bytes #xF4)) (cbor-simple 20)))
  (it "decodes true"
    (check-equal? (cbor-decode (bytes #xF5)) (cbor-simple 21)))
  (it "decodes null"
    (check-equal? (cbor-decode (bytes #xF6)) (cbor-simple 22)))
  (it "decodes undefined"
    (check-equal? (cbor-decode (bytes #xF7)) (cbor-simple 23)))
  (it "decodes simple(16)"
    (check-equal? (cbor-decode (bytes #xF0)) (cbor-simple 16)))
  (it "decodes float32 100000.0"
    (define result (cbor-decode (hex->bytes "FA 47 C3 50 00")))
    (check-pred cbor-float? result)
    (check-= (cbor-float-value result) 100000.0 0.01))
  (it "decodes float64 1.1"
    (define result (cbor-decode (hex->bytes "FB 3F F1 99 99 99 99 99 9A")))
    (check-pred cbor-float? result)
    (check-= (cbor-float-value result) 1.1 1e-10)))

;; ===== Round-trip tests =====

(describe "CBOR round-trip"
  (it "round-trips unsigned integers"
    (for ([n (list 0 1 23 24 255 256 65535 65536 1000000)])
      (check-equal? (cbor-decode (cbor-encode (cbor-unsigned n)))
                    (cbor-unsigned n))))
  (it "round-trips negative integers"
    (for ([n (list 0 9 99 999)])
      (check-equal? (cbor-decode (cbor-encode (cbor-negative n)))
                    (cbor-negative n))))
  (it "round-trips byte strings"
    (check-equal? (cbor-decode (cbor-encode (cbor-bytes (bytes 1 2 3))))
                  (cbor-bytes (bytes 1 2 3))))
  (it "round-trips text strings"
    (check-equal? (cbor-decode (cbor-encode (cbor-text "hello CBOR")))
                  (cbor-text "hello CBOR")))
  (it "round-trips arrays"
    (define v (cbor-array (list (cbor-unsigned 1) (cbor-text "two")
                                (cbor-array (list (cbor-unsigned 3))))))
    (check-equal? (cbor-decode (cbor-encode v)) v))
  (it "round-trips maps"
    (define v (cbor-map (list (cons (cbor-text "key") (cbor-unsigned 42)))))
    (check-equal? (cbor-decode (cbor-encode v)) v))
  (it "round-trips tags"
    (define v (cbor-tag 1 (cbor-unsigned 1000)))
    (check-equal? (cbor-decode (cbor-encode v)) v))
  (it "round-trips simple values"
    (for ([s (list 0 16 20 21 22 23 255)])
      (check-equal? (cbor-decode (cbor-encode (cbor-simple s)))
                    (cbor-simple s))))
  (it "round-trips float64"
    (define v (cbor-float 3.14159))
    (check-equal? (cbor-decode (cbor-encode v)) v)))

;; ===== Encoding test vectors =====

(describe "CBOR encoding matches RFC vectors"
  (it "encodes 0"
    (check-equal? (cbor-encode (cbor-unsigned 0)) (bytes #x00)))
  (it "encodes 24"
    (check-equal? (cbor-encode (cbor-unsigned 24)) (bytes #x18 #x18)))
  (it "encodes 1000"
    (check-equal? (cbor-encode (cbor-unsigned 1000)) (bytes #x19 #x03 #xE8)))
  (it "encodes -1"
    (check-equal? (cbor-encode (cbor-negative 0)) (bytes #x20)))
  (it "encodes empty array"
    (check-equal? (cbor-encode (cbor-array '())) (bytes #x80)))
  (it "encodes [1, 2, 3]"
    (check-equal? (cbor-encode (cbor-array (list (cbor-unsigned 1)
                                                  (cbor-unsigned 2)
                                                  (cbor-unsigned 3))))
                  (bytes #x83 #x01 #x02 #x03)))
  (it "encodes false"
    (check-equal? (cbor-encode cbor-false) (bytes #xF4)))
  (it "encodes true"
    (check-equal? (cbor-encode cbor-true) (bytes #xF5)))
  (it "encodes null"
    (check-equal? (cbor-encode cbor-null) (bytes #xF6))))

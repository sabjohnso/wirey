#lang racket/base

(require rackunit
         rackunit/spec
         racket/list
         racket/math
         wirey/protocols/cbor)

;; Helper
(define (hex->bytes str)
  (define clean (regexp-replace* #rx" " str ""))
  (apply bytes
         (for/list ([i (in-range 0 (string-length clean) 2)])
           (string->number (substring clean i (+ i 2)) 16))))

;; ============================================================
;; RFC 8949 Appendix A — Complete Decode Test Vectors
;; ============================================================

(describe "CBOR decode: unsigned integers (MT 0)"
  (it "0"      (check-equal? (cbor-decode (bytes #x00)) (cbor-unsigned 0)))
  (it "1"      (check-equal? (cbor-decode (bytes #x01)) (cbor-unsigned 1)))
  (it "10"     (check-equal? (cbor-decode (bytes #x0A)) (cbor-unsigned 10)))
  (it "23"     (check-equal? (cbor-decode (bytes #x17)) (cbor-unsigned 23)))
  (it "24"     (check-equal? (cbor-decode (bytes #x18 #x18)) (cbor-unsigned 24)))
  (it "25"     (check-equal? (cbor-decode (bytes #x18 #x19)) (cbor-unsigned 25)))
  (it "100"    (check-equal? (cbor-decode (bytes #x18 #x64)) (cbor-unsigned 100)))
  (it "255"    (check-equal? (cbor-decode (bytes #x18 #xFF)) (cbor-unsigned 255)))
  (it "256"    (check-equal? (cbor-decode (bytes #x19 #x01 #x00)) (cbor-unsigned 256)))
  (it "1000"   (check-equal? (cbor-decode (bytes #x19 #x03 #xE8)) (cbor-unsigned 1000)))
  (it "65535"  (check-equal? (cbor-decode (bytes #x19 #xFF #xFF)) (cbor-unsigned 65535)))
  (it "65536"  (check-equal? (cbor-decode (hex->bytes "1A 00 01 00 00")) (cbor-unsigned 65536)))
  (it "1000000" (check-equal? (cbor-decode (hex->bytes "1A 00 0F 42 40")) (cbor-unsigned 1000000)))
  (it "1000000000000"
    (check-equal? (cbor-decode (hex->bytes "1B 00 00 00 E8 D4 A5 10 00"))
                  (cbor-unsigned 1000000000000)))
  (it "18446744073709551615 (max uint64)"
    (check-equal? (cbor-decode (hex->bytes "1B FF FF FF FF FF FF FF FF"))
                  (cbor-unsigned 18446744073709551615))))

(describe "CBOR decode: negative integers (MT 1)"
  (it "-1"     (check-equal? (cbor-decode (bytes #x20)) (cbor-negative 0)))
  (it "-10"    (check-equal? (cbor-decode (bytes #x29)) (cbor-negative 9)))
  (it "-24"    (check-equal? (cbor-decode (bytes #x37)) (cbor-negative 23)))
  (it "-25"    (check-equal? (cbor-decode (bytes #x38 #x18)) (cbor-negative 24)))
  (it "-100"   (check-equal? (cbor-decode (bytes #x38 #x63)) (cbor-negative 99)))
  (it "-1000"  (check-equal? (cbor-decode (bytes #x39 #x03 #xE7)) (cbor-negative 999)))
  (it "-1000000"
    (check-equal? (cbor-decode (hex->bytes "3A 00 0F 42 3F")) (cbor-negative 999999)))
  (it "-18446744073709551616 (max negint)"
    (check-equal? (cbor-decode (hex->bytes "3B FF FF FF FF FF FF FF FF"))
                  (cbor-negative 18446744073709551615))))

(describe "CBOR decode: byte strings (MT 2)"
  (it "empty"  (check-equal? (cbor-decode (bytes #x40)) (cbor-bytes (bytes))))
  (it "h'01020304'"
    (check-equal? (cbor-decode (bytes #x44 #x01 #x02 #x03 #x04))
                  (cbor-bytes (bytes 1 2 3 4))))
  (it "24-byte length prefix"
    (define payload (make-bytes 32 #xAB))
    (define encoded (bytes-append (bytes #x58 32) payload))
    (check-equal? (cbor-decode encoded) (cbor-bytes payload))))

(describe "CBOR decode: text strings (MT 3)"
  (it "empty"  (check-equal? (cbor-decode (bytes #x60)) (cbor-text "")))
  (it "\"a\""  (check-equal? (cbor-decode (bytes #x61 #x61)) (cbor-text "a")))
  (it "\"IETF\""
    (check-equal? (cbor-decode (bytes #x64 #x49 #x45 #x54 #x46)) (cbor-text "IETF")))
  (it "\"\\\"\\\\\"" ;; "\"\\"
    (check-equal? (cbor-decode (bytes #x62 #x22 #x5C)) (cbor-text "\"\\")))
  (it "\"\\u00fc\" (ü)"
    (check-equal? (cbor-decode (bytes #x62 #xC3 #xBC)) (cbor-text "\u00fc")))
  (it "\"\\u6c34\" (水)"
    (check-equal? (cbor-decode (bytes #x63 #xE6 #xB0 #xB4)) (cbor-text "\u6c34")))
  (it "\"\\ud800\\udd51\" (𐅑, surrogate pair → U+10151)"
    (check-equal? (cbor-decode (bytes #x64 #xF0 #x90 #x85 #x91)) (cbor-text "\U00010151"))))

(describe "CBOR decode: arrays (MT 4)"
  (it "[]"     (check-equal? (cbor-decode (bytes #x80)) (cbor-array '())))
  (it "[1, 2, 3]"
    (check-equal? (cbor-decode (bytes #x83 #x01 #x02 #x03))
                  (cbor-array (list (cbor-unsigned 1) (cbor-unsigned 2) (cbor-unsigned 3)))))
  (it "[1, [2, 3], [4, 5]]"
    (define result (cbor-decode (hex->bytes "83 01 82 02 03 82 04 05")))
    (check-equal? (length (cbor-array-items result)) 3)
    (check-equal? (first (cbor-array-items result)) (cbor-unsigned 1))
    (check-equal? (second (cbor-array-items result))
                  (cbor-array (list (cbor-unsigned 2) (cbor-unsigned 3)))))
  (it "[0, 1, 2, ... 24] (25-element array, all inline)"
    ;; All values 0-23 encode as single bytes, value 24 encodes as #x18 #x18
    (define encoded (bytes-append (bytes #x98 25)
                                  (apply bytes (for/list ([i (in-range 0 24)]) i))
                                  (bytes #x18 24)))
    (define result (cbor-decode encoded))
    (check-equal? (length (cbor-array-items result)) 25)
    (check-equal? (first (cbor-array-items result)) (cbor-unsigned 0))
    (check-equal? (last (cbor-array-items result)) (cbor-unsigned 24))))

(describe "CBOR decode: maps (MT 5)"
  (it "{}"     (check-equal? (cbor-decode (bytes #xA0)) (cbor-map '())))
  (it "{1: 2, 3: 4}"
    (define result (cbor-decode (hex->bytes "A2 01 02 03 04")))
    (check-equal? (length (cbor-map-entries result)) 2)
    (check-equal? (car (first (cbor-map-entries result))) (cbor-unsigned 1))
    (check-equal? (cdr (first (cbor-map-entries result))) (cbor-unsigned 2))
    (check-equal? (car (second (cbor-map-entries result))) (cbor-unsigned 3))
    (check-equal? (cdr (second (cbor-map-entries result))) (cbor-unsigned 4)))
  (it "{\"a\": 1, \"b\": [2, 3]}"
    (define result (cbor-decode (hex->bytes "A2 61 61 01 61 62 82 02 03")))
    (check-equal? (length (cbor-map-entries result)) 2)
    (check-equal? (car (first (cbor-map-entries result))) (cbor-text "a"))
    (check-equal? (cdr (first (cbor-map-entries result))) (cbor-unsigned 1))
    (check-equal? (car (second (cbor-map-entries result))) (cbor-text "b"))
    (check-equal? (cdr (second (cbor-map-entries result)))
                  (cbor-array (list (cbor-unsigned 2) (cbor-unsigned 3)))))
  (it "{\"a\": \"A\", \"b\": \"B\", \"c\": \"C\", \"d\": \"D\", \"e\": \"E\"}"
    (define result (cbor-decode (hex->bytes
                     "A5 61 61 61 41 61 62 61 42 61 63 61 43 61 64 61 44 61 65 61 45")))
    (check-equal? (length (cbor-map-entries result)) 5)))

(describe "CBOR decode: tags (MT 6)"
  (it "tag 0 (date/time string)"
    (define result (cbor-decode (hex->bytes "C0 74 32 30 31 33 2D 30 33 2D 32 31 54 32 30 3A 30 34 3A 30 30 5A")))
    (check-equal? (cbor-tag-number result) 0)
    (check-equal? (cbor-tag-content result) (cbor-text "2013-03-21T20:04:00Z")))
  (it "tag 1 (epoch time)"
    (define result (cbor-decode (hex->bytes "C1 1A 51 4B 67 B0")))
    (check-equal? (cbor-tag-number result) 1)
    (check-equal? (cbor-tag-content result) (cbor-unsigned #x514B67B0)))
  (it "tag 23 (expected base16)"
    (define result (cbor-decode (hex->bytes "D7 44 01 02 03 04")))
    (check-equal? (cbor-tag-number result) 23)
    (check-equal? (cbor-tag-content result) (cbor-bytes (bytes 1 2 3 4))))
  (it "tag 24 (encoded CBOR)"
    (define result (cbor-decode (hex->bytes "D8 18 45 64 49 45 54 46")))
    (check-equal? (cbor-tag-number result) 24))
  (it "tag 32 (URI)"
    (define result (cbor-decode (hex->bytes "D8 20 76 68 74 74 70 3A 2F 2F 77 77 77 2E 65 78 61 6D 70 6C 65 2E 63 6F 6D")))
    (check-equal? (cbor-tag-number result) 32)
    (check-equal? (cbor-tag-content result) (cbor-text "http://www.example.com"))))

(describe "CBOR decode: simple values and floats (MT 7)"
  (it "false (20)" (check-equal? (cbor-decode (bytes #xF4)) (cbor-simple 20)))
  (it "true (21)"  (check-equal? (cbor-decode (bytes #xF5)) (cbor-simple 21)))
  (it "null (22)"  (check-equal? (cbor-decode (bytes #xF6)) (cbor-simple 22)))
  (it "undefined (23)" (check-equal? (cbor-decode (bytes #xF7)) (cbor-simple 23)))
  (it "simple(16)" (check-equal? (cbor-decode (bytes #xF0)) (cbor-simple 16)))
  (it "simple(255)" (check-equal? (cbor-decode (bytes #xF8 #xFF)) (cbor-simple 255)))
  ;; Half-precision floats
  (it "half 0.0"     (check-= (cbor-float-value (cbor-decode (hex->bytes "F9 00 00"))) 0.0 0))
  (it "half -0.0"    (check-= (cbor-float-value (cbor-decode (hex->bytes "F9 80 00"))) -0.0 0))
  (it "half 1.0"     (check-= (cbor-float-value (cbor-decode (hex->bytes "F9 3C 00"))) 1.0 0))
  (it "half 1.5"     (check-= (cbor-float-value (cbor-decode (hex->bytes "F9 3E 00"))) 1.5 0))
  (it "half 65504.0" (check-= (cbor-float-value (cbor-decode (hex->bytes "F9 7B FF"))) 65504.0 0))
  (it "half +Inf"    (check-equal? (cbor-float-value (cbor-decode (hex->bytes "F9 7C 00"))) +inf.0))
  (it "half NaN"     (check-true (nan? (cbor-float-value (cbor-decode (hex->bytes "F9 7E 00"))))))
  (it "half -Inf"    (check-equal? (cbor-float-value (cbor-decode (hex->bytes "F9 FC 00"))) -inf.0))
  ;; Single-precision floats
  (it "float32 100000.0"
    (check-= (cbor-float-value (cbor-decode (hex->bytes "FA 47 C3 50 00"))) 100000.0 0.01))
  (it "float32 3.4028234663852886e+38"
    (check-= (cbor-float-value (cbor-decode (hex->bytes "FA 7F 7F FF FF")))
             3.4028234663852886e+38 1e+31))
  (it "float32 +Inf"
    (check-equal? (cbor-float-value (cbor-decode (hex->bytes "FA 7F 80 00 00"))) +inf.0))
  (it "float32 NaN"
    (check-true (nan? (cbor-float-value (cbor-decode (hex->bytes "FA 7F C0 00 00"))))))
  ;; Double-precision floats
  (it "float64 1.1"
    (check-= (cbor-float-value (cbor-decode (hex->bytes "FB 3F F1 99 99 99 99 99 9A")))
             1.1 1e-15))
  (it "float64 1.0e+300"
    (check-= (cbor-float-value (cbor-decode (hex->bytes "FB 7E 37 E4 3C 88 00 75 9C")))
             1.0e+300 1e+285))
  (it "float64 -4.1"
    (check-= (cbor-float-value (cbor-decode (hex->bytes "FB C0 10 66 66 66 66 66 66")))
             -4.1 1e-15)))

;; ============================================================
;; Indefinite-length encoding
;; ============================================================

(describe "CBOR decode: indefinite-length byte strings"
  (it "(_ h'0102', h'030405') → h'0102030405'"
    (define result (cbor-decode (hex->bytes "5F 42 01 02 43 03 04 05 FF")))
    (check-equal? result (cbor-bytes (bytes 1 2 3 4 5)))))

(describe "CBOR decode: indefinite-length text strings"
  (it "(_ \"strea\", \"ming\") → \"streaming\""
    (define result (cbor-decode (hex->bytes "7F 65 73 74 72 65 61 64 6D 69 6E 67 FF")))
    (check-equal? result (cbor-text "streaming"))))

(describe "CBOR decode: indefinite-length arrays"
  (it "[_ ] (empty)"
    (check-equal? (cbor-decode (hex->bytes "9F FF")) (cbor-array '())))
  (it "[_ 1, [2, 3], [_ 4, 5]]"
    (define result (cbor-decode (hex->bytes "9F 01 82 02 03 9F 04 05 FF FF")))
    (check-equal? (length (cbor-array-items result)) 3)
    (check-equal? (first (cbor-array-items result)) (cbor-unsigned 1))
    (check-equal? (third (cbor-array-items result))
                  (cbor-array (list (cbor-unsigned 4) (cbor-unsigned 5)))))
  (it "[_ 0, 1, 2, ... 23]"
    (define encoded (bytes-append (bytes #x9F)
                                  (apply bytes (for/list ([i (in-range 0 24)]) i))
                                  (bytes #xFF)))
    (define result (cbor-decode encoded))
    (check-equal? (length (cbor-array-items result)) 24)))

(describe "CBOR decode: indefinite-length maps"
  (it "{_ \"a\": 1, \"b\": [_ 2, 3]}"
    (define result (cbor-decode (hex->bytes "BF 61 61 01 61 62 9F 02 03 FF FF")))
    (check-equal? (length (cbor-map-entries result)) 2)
    (check-equal? (car (first (cbor-map-entries result))) (cbor-text "a"))
    (check-equal? (cdr (second (cbor-map-entries result)))
                  (cbor-array (list (cbor-unsigned 2) (cbor-unsigned 3))))))

;; ============================================================
;; Encoding tests
;; ============================================================

(describe "CBOR encode: unsigned integers"
  (it "0"       (check-equal? (cbor-encode (cbor-unsigned 0)) (bytes #x00)))
  (it "1"       (check-equal? (cbor-encode (cbor-unsigned 1)) (bytes #x01)))
  (it "23"      (check-equal? (cbor-encode (cbor-unsigned 23)) (bytes #x17)))
  (it "24"      (check-equal? (cbor-encode (cbor-unsigned 24)) (bytes #x18 #x18)))
  (it "255"     (check-equal? (cbor-encode (cbor-unsigned 255)) (bytes #x18 #xFF)))
  (it "256"     (check-equal? (cbor-encode (cbor-unsigned 256)) (bytes #x19 #x01 #x00)))
  (it "1000"    (check-equal? (cbor-encode (cbor-unsigned 1000)) (bytes #x19 #x03 #xE8)))
  (it "65535"   (check-equal? (cbor-encode (cbor-unsigned 65535)) (bytes #x19 #xFF #xFF)))
  (it "65536"   (check-equal? (cbor-encode (cbor-unsigned 65536)) (hex->bytes "1A 00 01 00 00")))
  (it "1000000" (check-equal? (cbor-encode (cbor-unsigned 1000000)) (hex->bytes "1A 00 0F 42 40"))))

(describe "CBOR encode: negative integers"
  (it "-1"      (check-equal? (cbor-encode (cbor-negative 0)) (bytes #x20)))
  (it "-10"     (check-equal? (cbor-encode (cbor-negative 9)) (bytes #x29)))
  (it "-100"    (check-equal? (cbor-encode (cbor-negative 99)) (bytes #x38 #x63)))
  (it "-1000"   (check-equal? (cbor-encode (cbor-negative 999)) (bytes #x39 #x03 #xE7))))

(describe "CBOR encode: byte strings"
  (it "empty"   (check-equal? (cbor-encode (cbor-bytes (bytes))) (bytes #x40)))
  (it "h'01020304'"
    (check-equal? (cbor-encode (cbor-bytes (bytes 1 2 3 4)))
                  (bytes #x44 #x01 #x02 #x03 #x04))))

(describe "CBOR encode: text strings"
  (it "empty"   (check-equal? (cbor-encode (cbor-text "")) (bytes #x60)))
  (it "\"a\""   (check-equal? (cbor-encode (cbor-text "a")) (bytes #x61 #x61)))
  (it "\"IETF\""
    (check-equal? (cbor-encode (cbor-text "IETF")) (bytes #x64 #x49 #x45 #x54 #x46)))
  (it "\"\\u00fc\""
    (check-equal? (cbor-encode (cbor-text "\u00fc")) (bytes #x62 #xC3 #xBC))))

(describe "CBOR encode: arrays"
  (it "[]"      (check-equal? (cbor-encode (cbor-array '())) (bytes #x80)))
  (it "[1, 2, 3]"
    (check-equal? (cbor-encode (cbor-array (list (cbor-unsigned 1)
                                                  (cbor-unsigned 2)
                                                  (cbor-unsigned 3))))
                  (bytes #x83 #x01 #x02 #x03)))
  (it "nested arrays"
    (check-equal? (cbor-encode (cbor-array (list (cbor-unsigned 1)
                                                  (cbor-array (list (cbor-unsigned 2)
                                                                     (cbor-unsigned 3))))))
                  (hex->bytes "82 01 82 02 03"))))

(describe "CBOR encode: maps"
  (it "{}"      (check-equal? (cbor-encode (cbor-map '())) (bytes #xA0)))
  (it "{1: 2, 3: 4}"
    (check-equal? (cbor-encode (cbor-map (list (cons (cbor-unsigned 1) (cbor-unsigned 2))
                                                (cons (cbor-unsigned 3) (cbor-unsigned 4)))))
                  (hex->bytes "A2 01 02 03 04"))))

(describe "CBOR encode: tags"
  (it "tag 1"
    (check-equal? (cbor-encode (cbor-tag 1 (cbor-unsigned #x514B67B0)))
                  (hex->bytes "C1 1A 51 4B 67 B0"))))

(describe "CBOR encode: simple values"
  (it "false"   (check-equal? (cbor-encode cbor-false) (bytes #xF4)))
  (it "true"    (check-equal? (cbor-encode cbor-true) (bytes #xF5)))
  (it "null"    (check-equal? (cbor-encode cbor-null) (bytes #xF6)))
  (it "simple(16)" (check-equal? (cbor-encode (cbor-simple 16)) (bytes #xF0)))
  (it "simple(255)" (check-equal? (cbor-encode (cbor-simple 255)) (bytes #xF8 #xFF))))

;; ============================================================
;; Round-trip tests
;; ============================================================

(describe "CBOR round-trip"
  (it "unsigned integers"
    (for ([n (list 0 1 23 24 255 256 65535 65536 1000000
                   4294967295 4294967296 18446744073709551615)])
      (check-equal? (cbor-decode (cbor-encode (cbor-unsigned n)))
                    (cbor-unsigned n))))
  (it "negative integers"
    (for ([n (list 0 9 23 24 99 999 999999 18446744073709551615)])
      (check-equal? (cbor-decode (cbor-encode (cbor-negative n)))
                    (cbor-negative n))))
  (it "byte strings"
    (for ([bs (list (bytes) (bytes 1) (bytes 1 2 3) (make-bytes 100 #xAB))])
      (check-equal? (cbor-decode (cbor-encode (cbor-bytes bs)))
                    (cbor-bytes bs))))
  (it "text strings"
    (for ([s (list "" "a" "IETF" "hello world" "\u00fc" "\u6c34")])
      (check-equal? (cbor-decode (cbor-encode (cbor-text s)))
                    (cbor-text s))))
  (it "nested arrays"
    (define v (cbor-array (list (cbor-unsigned 1)
                                (cbor-text "two")
                                (cbor-array (list (cbor-unsigned 3)
                                                   (cbor-bytes (bytes 4 5)))))))
    (check-equal? (cbor-decode (cbor-encode v)) v))
  (it "maps with mixed keys"
    (define v (cbor-map (list (cons (cbor-text "key") (cbor-unsigned 42))
                              (cons (cbor-unsigned 1) (cbor-text "one")))))
    (check-equal? (cbor-decode (cbor-encode v)) v))
  (it "nested tags"
    (define v (cbor-tag 1 (cbor-tag 2 (cbor-unsigned 42))))
    (check-equal? (cbor-decode (cbor-encode v)) v))
  (it "simple values"
    (for ([s (list 0 1 16 19 20 21 22 23 32 255)])
      (check-equal? (cbor-decode (cbor-encode (cbor-simple s)))
                    (cbor-simple s))))
  (it "float64"
    (for ([f (list 0.0 1.0 -1.0 1.1 3.14159 1.0e+300 -4.1)])
      (check-equal? (cbor-decode (cbor-encode (cbor-float f)))
                    (cbor-float f))))
  (it "complex nested structure"
    (define v (cbor-map
                (list (cons (cbor-text "name") (cbor-text "wirey"))
                      (cons (cbor-text "version") (cbor-array (list (cbor-unsigned 1)
                                                                      (cbor-unsigned 3))))
                      (cons (cbor-text "data") (cbor-bytes (bytes 0 1 2 3)))
                      (cons (cbor-text "active") cbor-true)
                      (cons (cbor-text "tags") (cbor-array
                                                 (list (cbor-tag 32 (cbor-text "http://example.com"))
                                                       cbor-null))))))
    (check-equal? (cbor-decode (cbor-encode v)) v)))

;; ============================================================
;; Error handling
;; ============================================================

(describe "CBOR errors"
  (it "rejects reserved AI values (28-30)"
    (check-exn exn:fail? (λ () (cbor-decode (bytes #x1C))))
    (check-exn exn:fail? (λ () (cbor-decode (bytes #x1D))))
    (check-exn exn:fail? (λ () (cbor-decode (bytes #x1E)))))
  (it "rejects break as standalone item"
    (check-exn exn:fail? (λ () (cbor-decode (bytes #xFF))))))

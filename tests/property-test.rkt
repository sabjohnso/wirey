#lang racket/base

(require rackunit
         rackunit/spec
         racket/list
         wirey/field
         wirey/protocol
         wirey/codec
         wirey/length-expr
         wirey/protocols/cbor)

;; ============================================================
;; Property-Based Round-Trip Tests
;;
;; Algebra: ∀ pd vals. decode(encode(vals)) = vals
;; ============================================================

(define ITERATIONS 100)

;; --- Helpers ---

(define (string-trim-right s)
  (regexp-replace #rx" +$" s ""))

;; --- Random generators ---
;; Racket's random only handles up to ~4 billion. For larger widths,
;; we compose random bytes.

(define (random-uint width)
  (for/fold ([acc 0]) ([_ (in-range width)])
    (+ (* acc 256) (random 256))))

(define (random-sint width)
  (define half (expt 2 (sub1 (* 8 width))))
  (define raw (random-uint width))
  (if (>= raw half) (- raw (* 2 half)) raw))

(define (random-alpha width)
  (define chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
  (define len (random (add1 (min width 20))))
  (apply string (for/list ([_ (in-range len)])
                  (string-ref chars (random (string-length chars))))))

(define (random-octets width)
  (apply bytes (for/list ([_ (in-range width)])
                 (random 256))))

(define (random-bool) (if (zero? (random 2)) #f #t))

;; --- Property: uint round-trip ---

(describe "property: uint round-trip"
  (it "all widths and byte orders"
    (for ([width (list 1 2 4 8)])
      (for ([byte-order '(big little)])
        (define p (make-protocol-desc 'test
                    (list (make-field-desc 'val 'uint width byte-order))))
        (for ([_ (in-range ITERATIONS)])
          (define val (random-uint width))
          (define result (hash-ref (decode p (encode p (hasheq 'val val))) 'val))
          (check-equal? result val))))))

;; --- Property: sint round-trip ---

(describe "property: sint round-trip"
  (it "all widths and byte orders"
    (for ([width (list 1 2 4)])
      (for ([byte-order '(big little)])
        (define p (make-protocol-desc 'test
                    (list (make-field-desc 'val 'sint width byte-order))))
        (for ([_ (in-range ITERATIONS)])
          (define val (random-sint width))
          (define result (hash-ref (decode p (encode p (hasheq 'val val))) 'val))
          (check-equal? result val))))))

;; --- Property: alpha round-trip ---

(describe "property: alpha round-trip"
  (it "all widths"
    (for ([width (list 1 4 8 16)])
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'alpha width 'big))))
      (for ([_ (in-range ITERATIONS)])
        (define val (random-alpha width))
        (define result (hash-ref (decode p (encode p (hasheq 'val val))) 'val))
        (check-equal? result (string-trim-right val))))))

;; --- Property: octets round-trip ---

(describe "property: octets round-trip"
  (it "all widths"
    (for ([width (list 1 4 8 16)])
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'octets width 'big))))
      (for ([_ (in-range ITERATIONS)])
        (define val (random-octets width))
        (define result (hash-ref (decode p (encode p (hasheq 'val val))) 'val))
        (check-equal? result val)))))

;; --- Property: bool round-trip ---

(describe "property: bool round-trip"
  (it "round-trips"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'val 'bool 1 'big))))
    (for ([_ (in-range ITERATIONS)])
      (define val (random-bool))
      (define result (hash-ref (decode p (encode p (hasheq 'val val))) 'val))
      (check-equal? result val))))

;; --- Property: bitfield round-trip ---

(describe "property: bitfield round-trip (MSB)"
  (it "4+4 bit split"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'hi 'uint 4 'big #:unit 'bits)
                      (make-field-desc 'lo 'uint 4 'big #:unit 'bits))))
    (for ([_ (in-range ITERATIONS)])
      (define hi (random 16))
      (define lo (random 16))
      (define v (hasheq 'hi hi 'lo lo))
      (check-equal? (decode p (encode p v)) v)))

  (it "3+13 bit split"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'flags 'uint 3 'big #:unit 'bits)
                      (make-field-desc 'offset 'uint 13 'big #:unit 'bits))))
    (for ([_ (in-range ITERATIONS)])
      (define flags (random 8))
      (define offset (random 8192))
      (define v (hasheq 'flags flags 'offset offset))
      (check-equal? (decode p (encode p v)) v))))

(describe "property: bitfield round-trip (LSB)"
  (it "4+4 bit split"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'lo 'uint 4 'big #:unit 'bits #:bit-order 'lsb)
                      (make-field-desc 'hi 'uint 4 'big #:unit 'bits #:bit-order 'lsb))))
    (for ([_ (in-range ITERATIONS)])
      (define lo (random 16))
      (define hi (random 16))
      (define v (hasheq 'lo lo 'hi hi))
      (check-equal? (decode p (encode p v)) v))))

;; --- Property: multi-field protocol round-trip ---

(describe "property: multi-field protocol round-trip"
  (it "ITCH-like header"
    (define p (make-protocol-desc 'itch-header
                (list (make-field-desc 'msg-type 'alpha 1 'big)
                      (make-field-desc 'stock-locate 'uint 2 'big)
                      (make-field-desc 'tracking 'uint 2 'big)
                      (make-field-desc 'timestamp 'uint 6 'big))))
    (for ([_ (in-range ITERATIONS)])
      (define v (hasheq 'msg-type (random-alpha 1)
                        'stock-locate (random-uint 2)
                        'tracking (random-uint 2)
                        'timestamp (random-uint 6)))
      (check-equal? (decode p (encode p v)) v)))

  (it "mixed types"
    (define p (make-protocol-desc 'mixed
                (list (make-field-desc 'tag 'uint 1 'big)
                      (make-field-desc 'flag 'bool 1 'big)
                      (make-field-desc 'name 'alpha 8 'big)
                      (make-field-desc 'data 'octets 4 'big)
                      (make-field-desc 'value 'uint 4 'little))))
    (for ([_ (in-range ITERATIONS)])
      (define v (hasheq 'tag (random-uint 1)
                        'flag (random-bool)
                        'name (random-alpha 8)
                        'data (random-octets 4)
                        'value (random-uint 4)))
      (check-equal? (decode p (encode p v)) v))))

;; --- Property: variable-length round-trip ---

(describe "property: variable-length round-trip"
  (it "length-prefixed octets"
    (define p (make-protocol-desc 'var
                (list (make-field-desc 'len 'uint 2 'big)
                      (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))
    (for ([_ (in-range ITERATIONS)])
      (define len (random 64))
      (define data (random-octets len))
      (define v (hasheq 'len len 'data data))
      (check-equal? (decode p (encode p v)) v))))

;; --- Property: encode size consistency ---

(describe "property: encode size = total-size for fixed protocols"
  (it "uint fields all widths"
    (for ([width (list 1 2 4 8)])
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint width 'big))))
      (for ([_ (in-range 50)])
        (define bs (encode p (hasheq 'val (random-uint width))))
        (check-equal? (bytes-length bs) (protocol-desc-total-size p)))))

  (it "bitfield protocol"
    (define p (make-protocol-desc 'bits
                (list (make-field-desc 'a 'uint 4 'big #:unit 'bits)
                      (make-field-desc 'b 'uint 4 'big #:unit 'bits)
                      (make-field-desc 'c 'uint 2 'big))))
    (for ([_ (in-range 50)])
      (define bs (encode p (hasheq 'a (random 16) 'b (random 16) 'c (random-uint 2))))
      (check-equal? (bytes-length bs) (protocol-desc-total-size p)))))

;; --- Property: CBOR round-trip ---

(describe "property: CBOR round-trip"
  (it "unsigned integers"
    (for ([_ (in-range ITERATIONS)])
      (define n (random-uint 4))
      (define v (cbor-unsigned n))
      (check-equal? (cbor-decode (cbor-encode v)) v)))

  (it "negative integers"
    (for ([_ (in-range ITERATIONS)])
      (define n (random-uint 4))
      (define v (cbor-negative n))
      (check-equal? (cbor-decode (cbor-encode v)) v)))

  (it "byte strings"
    (for ([_ (in-range ITERATIONS)])
      (define len (random 128))
      (define v (cbor-bytes (random-octets len)))
      (check-equal? (cbor-decode (cbor-encode v)) v)))

  (it "text strings"
    (for ([_ (in-range ITERATIONS)])
      (define v (cbor-text (random-alpha (random 64))))
      (check-equal? (cbor-decode (cbor-encode v)) v)))

  (it "arrays of unsigned"
    (for ([_ (in-range 50)])
      (define items (for/list ([_ (in-range (random 10))])
                      (cbor-unsigned (random 1000))))
      (define v (cbor-array items))
      (check-equal? (cbor-decode (cbor-encode v)) v)))

  (it "maps"
    (for ([_ (in-range 50)])
      (define entries (for/list ([i (in-range (random 5))])
                        (cons (cbor-text (format "key~a" i))
                              (cbor-unsigned (random 1000)))))
      (define v (cbor-map entries))
      (check-equal? (cbor-decode (cbor-encode v)) v))))

;; --- Property: idempotence ---

(describe "property: decode is idempotent"
  (it "decoding the same bytes twice gives the same result"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'a 'uint 2 'big)
                      (make-field-desc 'b 'alpha 4 'big)
                      (make-field-desc 'c 'octets 3 'big))))
    (for ([_ (in-range ITERATIONS)])
      (define bs (encode p (hasheq 'a (random-uint 2)
                                   'b (random-alpha 4)
                                   'c (random-octets 3))))
      (check-equal? (decode p bs) (decode p bs)))))

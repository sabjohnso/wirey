#lang racket/base

(require rackunit
         rackunit/spec
         wirey/field
         wirey/length-expr)

(describe "field-type?"
  (context "given valid field types"
    (it "recognizes uint"
      (check-true (field-type? 'uint)))
    (it "recognizes sint"
      (check-true (field-type? 'sint)))
    (it "recognizes alpha"
      (check-true (field-type? 'alpha)))
    (it "recognizes octets"
      (check-true (field-type? 'octets)))
    (it "recognizes padding"
      (check-true (field-type? 'padding)))
    (it "recognizes float32"
      (check-true (field-type? 'float32)))
    (it "recognizes float64"
      (check-true (field-type? 'float64)))
    (it "recognizes bcd"
      (check-true (field-type? 'bcd)))
    (it "recognizes bool"
      (check-true (field-type? 'bool))))

  (context "given invalid values"
    (it "rejects unknown symbols"
      (check-false (field-type? 'float))
      (check-false (field-type? 'string)))
    (it "rejects non-symbols"
      (check-false (field-type? 42)))))

(describe "byte-order?"
  (context "given valid byte orders"
    (it "recognizes big"
      (check-true (byte-order? 'big)))
    (it "recognizes little"
      (check-true (byte-order? 'little))))

  (context "given invalid values"
    (it "rejects unknown symbols"
      (check-false (byte-order? 'host))
      (check-false (byte-order? 'network)))
    (it "rejects non-symbols"
      (check-false (byte-order? 42)))))

(describe "field-unit?"
  (context "given valid units"
    (it "recognizes bytes"
      (check-true (field-unit? 'bytes)))
    (it "recognizes bits"
      (check-true (field-unit? 'bits))))

  (context "given invalid values"
    (it "rejects unknown symbols"
      (check-false (field-unit? 'words))
      (check-false (field-unit? 'nibbles)))
    (it "rejects non-symbols"
      (check-false (field-unit? 8)))))

(describe "bit-order?"
  (context "given valid bit orders"
    (it "recognizes msb"
      (check-true (bit-order? 'msb)))
    (it "recognizes lsb"
      (check-true (bit-order? 'lsb))))

  (context "given invalid values"
    (it "rejects unknown symbols"
      (check-false (bit-order? 'big))
      (check-false (bit-order? 'network)))
    (it "rejects non-symbols"
      (check-false (bit-order? 42)))))

(describe "make-field-desc"
  (context "given valid arguments (byte-width fields)"
    (it "stores name, type, width, and byte-order"
      (define f (make-field-desc 'stock-locate 'uint 2 'big))
      (check-eq? (field-desc-name f) 'stock-locate)
      (check-eq? (field-desc-type f) 'uint)
      (check-equal? (field-desc-width f) 2)
      (check-eq? (field-desc-byte-order f) 'big))

    (it "defaults unit to bytes"
      (define f (make-field-desc 'val 'uint 4 'big))
      (check-eq? (field-desc-unit f) 'bytes))

    (it "supports all valid types"
      (check-not-exn (λ () (make-field-desc 'a 'uint 4 'big)))
      (check-not-exn (λ () (make-field-desc 'b 'sint 4 'big)))
      (check-not-exn (λ () (make-field-desc 'c 'alpha 8 'big)))
      (check-not-exn (λ () (make-field-desc 'd 'octets 6 'big))))

    (it "supports both byte orders"
      (check-not-exn (λ () (make-field-desc 'a 'uint 2 'big)))
      (check-not-exn (λ () (make-field-desc 'a 'uint 2 'little)))))

  (context "given valid arguments (bit-width fields)"
    (it "stores unit as bits when specified"
      (define f (make-field-desc 'version 'uint 4 'big #:unit 'bits))
      (check-eq? (field-desc-unit f) 'bits)
      (check-equal? (field-desc-width f) 4))

    (it "accepts various bit widths"
      (check-not-exn (λ () (make-field-desc 'a 'uint 1 'big #:unit 'bits)))
      (check-not-exn (λ () (make-field-desc 'b 'uint 3 'big #:unit 'bits)))
      (check-not-exn (λ () (make-field-desc 'c 'uint 13 'big #:unit 'bits))))

    (it "defaults bit-order to #f (inherit)"
      (define f (make-field-desc 'a 'uint 4 'big #:unit 'bits))
      (check-false (field-desc-bit-order f)))

    (it "stores bit-order when specified"
      (define f (make-field-desc 'a 'uint 4 'big #:unit 'bits #:bit-order 'lsb))
      (check-eq? (field-desc-bit-order f) 'lsb))

    (it "accepts msb bit-order"
      (check-not-exn
       (λ () (make-field-desc 'a 'uint 4 'big #:unit 'bits #:bit-order 'msb))))

    (it "rejects invalid bit-order"
      (check-exn exn:fail?
        (λ () (make-field-desc 'a 'uint 4 'big #:unit 'bits #:bit-order 'big))))

    (it "rejects bit-order on byte-unit fields"
      (check-exn exn:fail?
        (λ () (make-field-desc 'a 'uint 4 'big #:bit-order 'msb)))))

  (context "bitfield type restrictions"
    (it "rejects alpha with bits unit"
      (check-exn exn:fail? (λ () (make-field-desc 'a 'alpha 8 'big #:unit 'bits))))

    (it "rejects octets with bits unit"
      (check-exn exn:fail? (λ () (make-field-desc 'a 'octets 8 'big #:unit 'bits)))))

  (context "given invalid arguments"
    (it "rejects invalid type"
      (check-exn exn:fail? (λ () (make-field-desc 'a 'float 4 'big))))

    (it "rejects zero width"
      (check-exn exn:fail? (λ () (make-field-desc 'a 'uint 0 'big))))

    (it "rejects negative width"
      (check-exn exn:fail? (λ () (make-field-desc 'a 'uint -1 'big))))

    (it "rejects non-integer width"
      (check-exn exn:fail? (λ () (make-field-desc 'a 'uint 2.5 'big))))

    (it "rejects invalid byte-order"
      (check-exn exn:fail? (λ () (make-field-desc 'a 'uint 4 'network))))

    (it "rejects non-symbol name"
      (check-exn exn:fail? (λ () (make-field-desc "a" 'uint 4 'big))))

    (it "rejects invalid unit"
      (check-exn exn:fail? (λ () (make-field-desc 'a 'uint 4 'big #:unit 'words)))))

  (context "variable-length fields"
    (it "accepts a field-ref as width"
      (define f (make-field-desc 'data 'octets (make-field-ref 'incl-len) 'big))
      (check-true (field-ref? (field-desc-width f))))

    (it "accepts a compute as width"
      (define ce (make-compute '(* (- (field-ref ihl) 5) 4)
                               (λ (lk) (* (- (lk 'ihl) 5) 4))))
      (define f (make-field-desc 'options 'octets ce 'big))
      (check-true (compute? (field-desc-width f))))

    (it "reports as variable-length"
      (define f (make-field-desc 'data 'octets (make-field-ref 'len) 'big))
      (check-true (field-desc-variable-length? f)))

    (it "fixed-width fields are not variable-length"
      (define f (make-field-desc 'data 'octets 6 'big))
      (check-false (field-desc-variable-length? f)))

    (it "rejects bit-unit with variable length"
      (check-exn exn:fail?
        (λ () (make-field-desc 'a 'uint (make-field-ref 'x) 'big #:unit 'bits))))))

(describe "field-desc-contract"
  (it "defaults to #f (no contract)"
    (define f (make-field-desc 'val 'uint 4 'big))
    (check-false (field-desc-contract f)))

  (it "stores a contract predicate when provided"
    (define f (make-field-desc 'port 'uint 2 'big
                               #:contract (λ (v) (and (integer? v) (<= 0 v 65535)))))
    (check-pred procedure? (field-desc-contract f)))

  (it "has-contract? predicate works"
    (define f1 (make-field-desc 'val 'uint 4 'big))
    (define f2 (make-field-desc 'port 'uint 2 'big #:contract (λ (v) #t)))
    (check-false (field-desc-has-contract? f1))
    (check-true (field-desc-has-contract? f2))))

(describe "field-desc-present-when"
  (it "defaults to #f (always present)"
    (define f (make-field-desc 'val 'uint 4 'big))
    (check-false (field-desc-present-when f)))

  (it "stores a presence predicate when provided"
    (define f (make-field-desc 'val 'uint 4 'big
                               #:present-when (λ (lk) (> (lk 'flags) 0))))
    (check-pred procedure? (field-desc-present-when f)))

  (it "conditional? predicate works"
    (define f1 (make-field-desc 'val 'uint 4 'big))
    (define f2 (make-field-desc 'val 'uint 4 'big #:present-when (λ (lk) #t)))
    (check-false (field-desc-conditional? f1))
    (check-true (field-desc-conditional? f2))))

(describe "field-desc-compute"
  (it "defaults to #f (no compute function)"
    (define f (make-field-desc 'val 'uint 4 'big))
    (check-false (field-desc-compute f)))

  (it "stores a compute function when provided"
    (define (my-checksum buf) 42)
    (define f (make-field-desc 'chk 'uint 2 'big #:compute my-checksum))
    (check-equal? (field-desc-compute f) my-checksum))

  (it "computed? predicate works"
    (define f1 (make-field-desc 'val 'uint 4 'big))
    (define f2 (make-field-desc 'chk 'uint 2 'big #:compute (λ (buf) 0)))
    (check-false (field-desc-computed? f1))
    (check-true (field-desc-computed? f2))))

(describe "field-desc-width-in-bits"
  (it "returns width * 8 for byte-unit fields"
    (define f (make-field-desc 'val 'uint 2 'big))
    (check-equal? (field-desc-width-in-bits f) 16))

  (it "returns width directly for bit-unit fields"
    (define f (make-field-desc 'flags 'uint 3 'big #:unit 'bits))
    (check-equal? (field-desc-width-in-bits f) 3)))

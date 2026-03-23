#lang racket/base

(require rackunit
         rackunit/spec
         wirey/field)

(describe "field-type?"
  (context "given valid field types"
    (it "recognizes uint"
      (check-true (field-type? 'uint)))
    (it "recognizes sint"
      (check-true (field-type? 'sint)))
    (it "recognizes alpha"
      (check-true (field-type? 'alpha)))
    (it "recognizes octets"
      (check-true (field-type? 'octets))))

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

(describe "make-field-desc"
  (context "given valid arguments"
    (it "stores name, type, width, and byte-order"
      (define f (make-field-desc 'stock-locate 'uint 2 'big))
      (check-eq? (field-desc-name f) 'stock-locate)
      (check-eq? (field-desc-type f) 'uint)
      (check-equal? (field-desc-width f) 2)
      (check-eq? (field-desc-byte-order f) 'big))

    (it "supports all valid types"
      (check-not-exn (λ () (make-field-desc 'a 'uint 4 'big)))
      (check-not-exn (λ () (make-field-desc 'b 'sint 4 'big)))
      (check-not-exn (λ () (make-field-desc 'c 'alpha 8 'big)))
      (check-not-exn (λ () (make-field-desc 'd 'octets 6 'big))))

    (it "supports both byte orders"
      (check-not-exn (λ () (make-field-desc 'a 'uint 2 'big)))
      (check-not-exn (λ () (make-field-desc 'a 'uint 2 'little)))))

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
      (check-exn exn:fail? (λ () (make-field-desc "a" 'uint 4 'big))))))

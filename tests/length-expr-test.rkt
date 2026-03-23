#lang racket/base

(require rackunit
         rackunit/spec
         wirey/length-expr)

(describe "length-expr?"
  (it "recognizes a fixed integer as a length expression"
    (check-true (length-expr? 4))
    (check-true (length-expr? 100)))

  (it "recognizes a field-ref"
    (check-true (length-expr? (make-field-ref 'incl-len))))

  (it "recognizes a compute expression"
    (check-true (length-expr? (make-compute '(* (- (field-ref ihl) 5) 4)
                                            (λ (lookup) (* (- (lookup 'ihl) 5) 4))))))

  (it "rejects other values"
    (check-false (length-expr? "bad"))
    (check-false (length-expr? 'bad))
    (check-false (length-expr? -1))))

(describe "make-field-ref"
  (it "stores the referenced field name"
    (define fr (make-field-ref 'incl-len))
    (check-eq? (field-ref-name fr) 'incl-len))

  (it "rejects non-symbol names"
    (check-exn exn:fail? (λ () (make-field-ref "bad")))))

(describe "eval-length-expr"
  (define (lookup name)
    (case name
      [(incl-len) 64]
      [(ihl) 5]
      [else (error 'lookup "unknown field: ~a" name)]))

  (it "returns a fixed integer as-is"
    (check-equal? (eval-length-expr 4 lookup) 4))

  (it "evaluates a field-ref by looking up the field value"
    (check-equal? (eval-length-expr (make-field-ref 'incl-len) lookup) 64))

  (it "evaluates a compute expression"
    (define ce (make-compute '(* (- (field-ref ihl) 5) 4)
                             (λ (lookup) (* (- (lookup 'ihl) 5) 4))))
    (check-equal? (eval-length-expr ce lookup) 0))

  (it "evaluates a compute with ihl=7 yielding 8 bytes of options"
    (define ce (make-compute '(* (- (field-ref ihl) 5) 4)
                             (λ (lk) (* (- (lk 'ihl) 5) 4))))
    (define (lookup7 name)
      (case name [(ihl) 7] [else (error 'lookup "unknown")]))
    (check-equal? (eval-length-expr ce lookup7) 8)))

(describe "fixed-length-expr?"
  (it "returns #t for integers"
    (check-true (fixed-length-expr? 4)))

  (it "returns #f for field-ref"
    (check-false (fixed-length-expr? (make-field-ref 'x))))

  (it "returns #f for compute"
    (check-false (fixed-length-expr? (make-compute '() (λ (lk) 0))))))

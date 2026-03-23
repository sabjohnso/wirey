#lang racket/base

(provide make-case-block
         case-block?
         case-block-discriminator
         case-block-branches
         make-case-branch
         case-branch?
         case-branch-predicate
         case-branch-fields
         case-block-select-branch)

;; A case-branch has:
;;   predicate : (or/c exact-integer? procedure?) — exact match or predicate
;;   fields    : (listof field-desc?)
(struct case-branch (predicate fields) #:transparent)

(define (make-case-branch pred-or-val fields)
  (case-branch pred-or-val fields))

;; A case-block has:
;;   discriminator : symbol (name of the field to dispatch on)
;;   branches      : (listof case-branch?)
(struct case-block (discriminator branches) #:transparent)

(define (make-case-block discriminator branches)
  (case-block discriminator branches))

;; Select the matching branch for a given discriminator value.
;; Returns the case-branch or #f.
(define (case-block-select-branch cb disc-val)
  (for/first ([br (in-list (case-block-branches cb))]
              #:when (let ([pred (case-branch-predicate br)])
                       (if (procedure? pred)
                           (pred disc-val)
                           (equal? pred disc-val))))
    br))

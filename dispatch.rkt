#lang racket/base

(require (for-syntax racket/base
                     racket/syntax
                     syntax/parse)
         racket/list
         wirey/field
         wirey/codec)

(provide make-dispatch-desc
         dispatch-desc?
         dispatch-desc-name
         dispatch-decode
         define-dispatch)

;; ============================================================
;; Dispatch descriptor
;; ============================================================

;; A dispatch-desc has:
;;   name       : symbol
;;   offset     : exact-nonneg-integer? (byte offset of discriminator)
;;   width      : exact-positive-integer? (byte width of discriminator)
;;   type       : symbol ('uint, 'sint, 'alpha, 'octets)
;;   byte-order : symbol ('big, 'little)
;;   table      : hash (discriminator-value → (list protocol-desc decode-fn pred-fn))
(struct dispatch-desc (name offset width type byte-order table) #:transparent)

(define (make-dispatch-desc name
                            #:offset offset
                            #:width width
                            #:type type
                            #:byte-order byte-order
                            entries)
  (define tbl
    (for/hash ([e (in-list entries)])
      (values (car e) (cdr e))))
  (dispatch-desc name offset width type byte-order tbl))

;; ============================================================
;; Dispatch decoding
;; ============================================================

(define (dispatch-decode dd data #:offset [start 0])
  (define disc-offset (+ start (dispatch-desc-offset dd)))
  (define disc-width (dispatch-desc-width dd))
  (define disc-type (dispatch-desc-type dd))
  (define disc-order (dispatch-desc-byte-order dd))
  ;; Read the discriminator
  (define fd (make-field-desc 'discriminator disc-type disc-width disc-order))
  (define disc-val (decode-field data disc-offset fd))
  ;; Look up in dispatch table
  (define entry (hash-ref (dispatch-desc-table dd) disc-val #f))
  (if entry
      (let ([decode-fn (second entry)])
        (decode-fn data #:offset start))
      #f))

;; ============================================================
;; define-dispatch macro
;; ============================================================

;; Syntax:
;;   (define-dispatch name
;;     #:offset n
;;     #:width  n
;;     #:type   type-id
;;     [(value) wire-struct] ...)
;;
;; Generates:
;;   name        — dispatch-desc
;;   name-decode — bytes [#:offset n] → wire-struct-instance or #f

(define-syntax (define-dispatch stx)
  (syntax-parse stx
    [(_ dname:id
        #:offset disc-offset:nat
        #:width  disc-width:nat
        #:type   disc-type:id
        [(val) ws:id] ...)
     (with-syntax ([decode-id (format-id #'dname "~a-decode" #'dname)]
                   [(ws-decode ...) (map (λ (w) (format-id w "~a-decode" w))
                                         (syntax->list #'(ws ...)))]
                   [(ws-pred ...) (map (λ (w) (format-id w "~a?" w))
                                       (syntax->list #'(ws ...)))])
       #'(begin
           (define dname
             (make-dispatch-desc 'dname
               #:offset disc-offset
               #:width  disc-width
               #:type   'disc-type
               #:byte-order 'big
               (list (cons val (list ws ws-decode ws-pred)) ...)))
           (define (decode-id data #:offset [offset 0])
             (dispatch-decode dname data #:offset offset))))]))

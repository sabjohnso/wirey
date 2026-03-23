#lang racket/base

(require (for-syntax racket/base
                     racket/syntax
                     syntax/parse)
         wirey/field
         wirey/protocol
         wirey/codec)

(provide define-protocol)

(define-syntax (define-protocol stx)
  (syntax-parse stx
    [(_ proto-name:id
        (~optional (~seq #:byte-order default-bo:id)
                   #:defaults ([default-bo #'big]))
        field-clause ...)
     (with-syntax ([proto-desc-id (format-id #'proto-name "~a-protocol" #'proto-name)]
                   [encode-id     (format-id #'proto-name "~a-encode" #'proto-name)]
                   [decode-id     (format-id #'proto-name "~a-decode" #'proto-name)])
       #`(begin
           (define proto-desc-id
             (make-protocol-desc
              'proto-name
              (list #,@(for/list ([fc (in-list (syntax->list #'(field-clause ...)))])
                         (syntax-parse fc
                           [(fname:id ftype:id fwidth:nat (~optional (~seq #:byte-order fbo:id)))
                            #'(make-field-desc 'fname 'ftype fwidth
                                               (~? 'fbo 'default-bo))])))))
           (define (encode-id values)
             (encode proto-desc-id values))
           (define (decode-id data #:offset [offset 0])
             (decode proto-desc-id data #:offset offset))))]))

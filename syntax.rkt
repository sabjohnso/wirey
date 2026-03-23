#lang racket/base

(require (for-syntax racket/base
                     racket/syntax
                     racket/list
                     syntax/parse)
         racket/match
         wirey/field
         wirey/protocol
         wirey/codec)

(provide struct/wire)

;; ============================================================
;; Helper: build a match expander that dispatches on keyword
;; field accessors. Called at runtime by the match expander.
;; ============================================================

;; wire-struct-match-transform : predicate (listof (cons keyword accessor)) stx → stx
;; Used by generated match expanders to produce match patterns.
(define-for-syntax (wire-struct-match-transform pred-id accessor-table pat-stx)
  (syntax-parse pat-stx
    [(_)
     #`(? #,pred-id)]
    [(_ (~seq kw:keyword pat) ...)
     #`(? #,pred-id
          #,@(for/list ([k (in-list (syntax->list #'(kw ...)))]
                        [p (in-list (syntax->list #'(pat ...)))])
               (define kw-str (keyword->string (syntax-e k)))
               (define acc (hash-ref accessor-table kw-str
                             (λ () (raise-syntax-error
                                    'match
                                    (format "unknown field keyword ~a" (syntax-e k))
                                    k))))
               #`(app #,acc #,p)))]))

;; ============================================================
;; struct/wire macro
;; ============================================================

(define-syntax (struct/wire stx)
  (syntax-parse stx
    [(_ sname:id
        (~optional (~seq #:byte-order default-bo:id)
                   #:defaults ([default-bo #'big]))
        field-clause ...)

     ;; Parse field clauses
     (define field-infos
       (for/list ([fc (in-list (syntax->list #'(field-clause ...)))])
         (syntax-parse fc
           [(fname:id ftype:id fwidth:nat
                      (~optional (~seq #:byte-order fbo:id)))
            (list #'fname #'ftype #'fwidth (attribute fbo))])))

     (define field-names  (map first field-infos))
     (define field-widths (map third field-infos))

     ;; Compute byte offsets
     (define field-offsets
       (let loop ([infos field-infos] [off 0] [acc '()])
         (if (null? infos)
             (reverse acc)
             (loop (cdr infos)
                   (+ off (syntax-e (third (car infos))))
                   (cons off acc)))))

     ;; Keywords from field names
     (define field-kws
       (map (λ (fn) (string->keyword (symbol->string (syntax-e fn))))
            field-names))

     ;; Sorted indices for keyword arg ordering
     (define sorted-idxs
       (sort (range (length field-kws))
             keyword<? #:key (λ (i) (list-ref field-kws i))))

     ;; Identifiers
     (define instance-id (generate-temporary (format-id #'sname "~a-inst" #'sname)))
     (define inst-pred   (format-id instance-id "~a?" instance-id))
     (define inst-bytes  (format-id instance-id "~a-bytes" instance-id))
     (define inst-offset (format-id instance-id "~a-offset" instance-id))
     (define desc-id     (generate-temporary #'sname))
     (define pred-id     (format-id #'sname "~a?" #'sname))
     (define encode-id   (format-id #'sname "~a-encode" #'sname))
     (define decode-id   (format-id #'sname "~a-decode" #'sname))

     (define accessor-ids
       (map (λ (fn) (format-id #'sname "~a-~a" #'sname fn))
            field-names))

     ;; Field descriptor expressions
     (define fd-exprs
       (for/list ([info field-infos])
         (define fn (first info))
         (define ft (second info))
         (define fw (third info))
         (define fb (fourth info))
         (if fb
             #`(make-field-desc '#,fn '#,ft #,fw '#,fb)
             #`(make-field-desc '#,fn '#,ft #,fw 'default-bo))))

     ;; Encode function formals (sorted keyword args)
     (define sorted-params
       (for/list ([i sorted-idxs])
         (generate-temporary (list-ref field-names i))))

     (define encode-formals
       (apply append
              (for/list ([i sorted-idxs]
                         [param sorted-params])
                (list (datum->syntax #'sname (list-ref field-kws i))
                      param))))

     (define encode-hash-pairs
       (apply append
              (for/list ([i sorted-idxs]
                         [param sorted-params])
                (define fn (list-ref field-names i))
                (list #`'#,fn param))))

     ;; Accessor definitions
     (define accessor-defs
       (for/list ([aid accessor-ids]
                  [fn field-names]
                  [off field-offsets])
         #`(define (#,aid v)
             (decode-field (#,inst-bytes v)
                           (+ (#,inst-offset v) #,off)
                           (protocol-desc-field-ref #,desc-id '#,fn)))))

     ;; Accessor table for match expander (keyword-string → accessor-id)
     (define accessor-table-for-match
       (for/list ([fn field-names]
                  [aid accessor-ids])
         (cons (symbol->string (syntax-e fn)) aid)))

     #`(begin
         ;; Instance struct (hidden name)
         (struct #,instance-id (bytes offset))

         ;; Protocol descriptor (hidden binding)
         (define #,desc-id
           (make-protocol-desc 'sname (list #,@fd-exprs)))

         ;; Predicate
         (define (#,pred-id v) (#,inst-pred v))

         ;; Field accessors
         #,@accessor-defs

         ;; Encode: keyword args → bytes
         (define (#,encode-id #,@encode-formals)
           (encode #,desc-id (hasheq #,@encode-hash-pairs)))

         ;; Decode: bytes [#:offset n] → instance
         (define (#,decode-id data #:offset [offset 0])
           (#,instance-id data offset))

         ;; Match expander + expression transformer
         (define-match-expander sname
           ;; Match transformer
           (λ (pat-stx)
             (wire-struct-match-transform
              #'#,pred-id
              (hash #,@(apply
                        append
                        (for/list ([entry accessor-table-for-match])
                          (list (car entry) #`#'#,(cdr entry)))))
              pat-stx))
           ;; Expression transformer — evaluates to protocol descriptor
           (λ (expr-stx) #'#,desc-id)))]))

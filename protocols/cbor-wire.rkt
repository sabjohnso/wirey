#lang racket/base

;; ============================================================
;; CBOR Wire Structure (RFC 8949)
;;
;; Definite-length CBOR items expressed via struct/wire.
;; This proves wirey's DSL can describe self-describing recursive
;; formats. Indefinite-length encoding is handled by a thin
;; wrapper that reuses this definition.
;; ============================================================

(require wirey/syntax
         wirey/protocol
         wirey/codec)

(provide (all-defined-out))

;; The core CBOR wire structure.
;; Each item has an initial byte (major-type + additional-info),
;; an optional extended argument, and a type-dependent payload.
(struct/wire cbor-wire-item
  #:byte-order big
  (major-type       uint 3 #:unit bits)
  (additional-info  uint 5 #:unit bits)
  ;; Extended argument: depends on additional-info
  (#:case additional-info
    [((λ (v) (<= v 23)))]         ;; argument is inline (= additional-info)
    [(24) (ext-arg uint 1)]        ;; 1-byte argument
    [(25) (ext-arg uint 2)]        ;; 2-byte argument
    [(26) (ext-arg uint 4)]        ;; 4-byte argument
    [(27) (ext-arg uint 8)])       ;; 8-byte argument
  ;; Payload: depends on major-type
  ;; The effective argument is (or ext-arg additional-info)
  (#:case major-type
    [(0)]                          ;; unsigned int — no payload
    [(1)]                          ;; negative int — no payload
    [(2) (payload octets           ;; byte string
           (compute (λ (lk) (or (lk 'ext-arg) (lk 'additional-info)))))]
    [(3) (payload octets           ;; text string (UTF-8 bytes)
           (compute (λ (lk) (or (lk 'ext-arg) (lk 'additional-info)))))]
    [(4) (items cbor-wire-item     ;; array
           #:repeat (compute (λ (lk) (or (lk 'ext-arg) (lk 'additional-info))))
           #:struct)]
    [(5) (pairs cbor-wire-item     ;; map (2 × count items: k1,v1,k2,v2,...)
           #:repeat (compute (λ (lk) (* 2 (or (lk 'ext-arg) (lk 'additional-info)))))
           #:struct)]
    [(6) (tagged cbor-wire-item    ;; tag — one content item
           #:struct)]
    [(7)]))                        ;; simple/float — no payload (value in argument)

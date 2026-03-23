#lang scribble/manual

@require[@for-label[wirey
                    wirey/field
                    wirey/protocol
                    wirey/codec
                    wirey/syntax
                    racket/base]]

@title{wirey: Binary Wire Protocol Specifications}
@author{sbj}

@defmodule[wirey]

Wirey is a Racket library for declaratively specifying binary wire protocols.
It provides both a data-driven description layer and a macro surface syntax
for defining protocol message formats, with automatic generation of
encoder and decoder functions.

Wirey currently supports byte-aligned, fixed-width fields with configurable
byte order. Field types include unsigned integers, signed integers
(two's complement), fixed-width ASCII strings, and raw byte sequences.

@table-of-contents[]

@; ------------------------------------------------------------------
@section{Quick Start}

Define a protocol with @racket[define-protocol], then use the generated
encode and decode functions:

@racketblock[
(require wirey)

(define-protocol udp-header
  #:byte-order big
  (src-port   uint 2)
  (dst-port   uint 2)
  (length     uint 2)
  (checksum   uint 2))

(define pkt
  (udp-header-encode
   (hasheq 'src-port  49152
           'dst-port  53
           'length    42
           'checksum  0)))

(udp-header-decode pkt)
]

The macro @racket[define-protocol] introduces three bindings:
@itemlist[
  @item{@racketvarfont{name}@racketidfont{-protocol} — a @racket[protocol-desc] value}
  @item{@racketvarfont{name}@racketidfont{-encode} — a function from @racket[hash] to @racket[bytes]}
  @item{@racketvarfont{name}@racketidfont{-decode} — a function from @racket[bytes] to @racket[hash]}
]

@; ------------------------------------------------------------------
@section{Field Descriptors}

@defmodule[wirey/field]

A @deftech{field descriptor} describes a single field in a binary layout:
its name, type, byte width, and byte order.

@defproc[(make-field-desc [name symbol?]
                          [type field-type?]
                          [width exact-positive-integer?]
                          [byte-order byte-order?])
         field-desc?]{
Creates a field descriptor. Raises @racket[exn:fail?] if any argument
is invalid.}

@defproc[(field-desc? [v any/c]) boolean?]{
Returns @racket[#t] if @racket[v] is a field descriptor.}

@defproc[(field-desc-name [fd field-desc?]) symbol?]{
The field's symbolic name.}

@defproc[(field-desc-type [fd field-desc?]) field-type?]{
The field's type.}

@defproc[(field-desc-width [fd field-desc?]) exact-positive-integer?]{
The field's width in bytes.}

@defproc[(field-desc-byte-order [fd field-desc?]) byte-order?]{
The field's byte order.}

@defproc[(field-type? [v any/c]) boolean?]{
Returns @racket[#t] if @racket[v] is a valid field type symbol.
Valid types are:

@itemlist[
  @item{@racket['uint] — unsigned integer}
  @item{@racket['sint] — signed integer (two's complement)}
  @item{@racket['alpha] — fixed-width ASCII string, right-padded with spaces}
  @item{@racket['octets] — raw bytes}
]}

@defproc[(byte-order? [v any/c]) boolean?]{
Returns @racket[#t] if @racket[v] is a valid byte order symbol:
@racket['big] or @racket['little].}

@; ------------------------------------------------------------------
@section{Protocol Descriptors}

@defmodule[wirey/protocol]

A @deftech{protocol descriptor} groups a sequence of field descriptors
into a named binary message format.

@defproc[(make-protocol-desc [name symbol?]
                             [fields (listof field-desc?)])
         protocol-desc?]{
Creates a protocol descriptor. Raises @racket[exn:fail?] if any argument
is invalid.}

@defproc[(protocol-desc? [v any/c]) boolean?]{
Returns @racket[#t] if @racket[v] is a protocol descriptor.}

@defproc[(protocol-desc-name [pd protocol-desc?]) symbol?]{
The protocol's symbolic name.}

@defproc[(protocol-desc-fields [pd protocol-desc?]) (listof field-desc?)]{
The protocol's ordered list of field descriptors.}

@defproc[(protocol-desc-total-size [pd protocol-desc?]) exact-nonneg-integer?]{
The total size of the protocol in bytes (sum of all field widths).}

@defproc[(protocol-desc-field-ref [pd protocol-desc?]
                                  [name symbol?])
         (or/c field-desc? #f)]{
Looks up a field by name. Returns @racket[#f] if no field with
the given name exists.}

@; ------------------------------------------------------------------
@section{Codec}

@defmodule[wirey/codec]

The codec module provides generic encode and decode operations
that work with any @tech{protocol descriptor}.

@defproc[(encode [pd protocol-desc?]
                 [values (hash/c symbol? any/c)])
         bytes?]{
Encodes @racket[values] according to the protocol descriptor @racket[pd].
The @racket[values] hash must contain an entry for every field name in the
protocol. Returns a byte string of length @racket[(protocol-desc-total-size pd)].

Encoding rules by field type:

@itemlist[
  @item{@racket['uint] — value must be an exact non-negative integer.
    Encoded in the field's byte order.}
  @item{@racket['sint] — value must be an exact integer.
    Encoded as two's complement in the field's byte order.}
  @item{@racket['alpha] — value must be a string. Left-justified and
    right-padded with spaces to the field width. Truncated if longer.}
  @item{@racket['octets] — value must be a byte string. Copied directly.
    Truncated if longer than the field width.}
]}

@defproc[(decode [pd protocol-desc?]
                 [data bytes?]
                 [#:offset offset exact-nonneg-integer? 0])
         (hash/c symbol? any/c)]{
Decodes @racket[data] starting at @racket[offset] according to the
protocol descriptor @racket[pd]. Returns a hash mapping field names
to decoded values.

Decoding rules by field type:

@itemlist[
  @item{@racket['uint] — returns an exact non-negative integer.}
  @item{@racket['sint] — returns an exact integer (negative values
    reconstructed from two's complement).}
  @item{@racket['alpha] — returns a string with trailing spaces removed.}
  @item{@racket['octets] — returns a byte string.}
]}

@; ------------------------------------------------------------------
@section{Macro Syntax}

@defmodule[wirey/syntax]

@defform[(define-protocol name
           maybe-byte-order
           field-spec ...)
         #:grammar
         ([maybe-byte-order (code:line)
                            (code:line #:byte-order byte-order-id)]
          [field-spec (field-name type-id width-nat)
                      (field-name type-id width-nat #:byte-order byte-order-id)])]{
Defines a binary protocol and introduces three bindings:

@itemlist[
  @item{@racketvarfont{name}@racketidfont{-protocol} — a @racket[protocol-desc] value
    describing the layout}
  @item{@racketvarfont{name}@racketidfont{-encode} — @racket[(-> (hash/c symbol? any/c) bytes?)],
    encodes a hash of field values to bytes}
  @item{@racketvarfont{name}@racketidfont{-decode} — @racket[(->* (bytes?) (#:offset exact-nonneg-integer?) (hash/c symbol? any/c))],
    decodes bytes to a hash of field values}
]

The optional @racket[#:byte-order] clause sets the default byte order
for all fields (defaults to @racket[big]). Individual fields can
override the default with their own @racket[#:byte-order] clause.

@racketblock[
(define-protocol pcap-record
  #:byte-order little
  (ts-sec    uint 4)
  (ts-usec   uint 4)
  (incl-len  uint 4)
  (orig-len  uint 4))

(define-protocol mixed
  #:byte-order big
  (network-field  uint 2)
  (host-field     uint 2 #:byte-order little))
]}

@; ------------------------------------------------------------------
@section{Bundled Protocol Definitions}

Wirey ships with definitions for several common protocols.

@subsection{ITCH 5.0}

@defmodule[wirey/protocols/itch]

NASDAQ TotalView-ITCH 5.0 message definitions. All fields are big-endian.
Prices are unsigned integers with implied decimal places (not encoded on
the wire).

Defined protocols:

@itemlist[
  @item{@racket[itch-system-event-protocol] — System Event (type @racket["S"], 12 bytes)}
  @item{@racket[itch-add-order-protocol] — Add Order without MPID (type @racket["A"], 36 bytes)}
  @item{@racket[itch-add-order-mpid-protocol] — Add Order with MPID (type @racket["F"], 40 bytes)}
  @item{@racket[itch-order-executed-protocol] — Order Executed (type @racket["E"], 31 bytes)}
  @item{@racket[itch-order-delete-protocol] — Order Delete (type @racket["D"], 19 bytes)}
  @item{@racket[itch-trade-protocol] — Trade, Non-Cross (type @racket["P"], 44 bytes)}
]

Each protocol provides the standard @racketidfont{-protocol},
@racketidfont{-encode}, and @racketidfont{-decode} bindings.

@subsection{PCAP}

@defmodule[wirey/protocols/pcap]

PCAP capture file headers. Default byte order is little-endian
(the common case for native captures).

@itemlist[
  @item{@racket[pcap-global-header-protocol] — Global file header (24 bytes)}
  @item{@racket[pcap-record-header-protocol] — Per-packet record header (16 bytes)}
]

@subsection{Ethernet}

@defmodule[wirey/protocols/ethernet]

@itemlist[
  @item{@racket[ethernet-header-protocol] — Ethernet frame header (14 bytes):
    destination MAC, source MAC, and EtherType}
]

@subsection{UDP}

@defmodule[wirey/protocols/udp]

@itemlist[
  @item{@racket[udp-header-protocol] — UDP datagram header (8 bytes)}
]

pbkdf2_nif
==========

A [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) implementation for [Erlang](http://www.erlang.org/) applications provided as a nif.

This implementation is using an HMAC_SHA1 algorithm. It's based on source code from the [OpenBSD](https://openbsd.org) project.

For a pure Erlang implementation you can use [erlang-pbkdf2](https://github.com/basho/erlang-pbkdf2).

Usage
-----

```erlang
1> Password = <<"password">>,
1> Salt = <<"ATHENA.MIT.EDUraeburn">>,
1> NbRounds = 1200,
1> pbkdf2:pbkdf2(Password, Salt, NbRounds).
<<92,8,235,97,253,247,30,78,78,195,207,107,161,245,81,43,
  167,229,45,219>>
```


Build
-----

    $ rebar3 compile

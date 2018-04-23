# codestyle

## Namespaces

The Nabto Embedded SDK is under the namespace `nabto_` for functions and
types an `NABTO_` for constants and macros.


## Indentation

Indentation is 4 spaces


## Function names

Use underscores and lowercase.

```
void nabto_module_function()
{

}
```

## Structs and Enums

```
enum nabto_ip_address_type {
    NABTO_IPV4,
    NABTO_IPv6
};
```


Use camelcase for struct properties.
```
struct nabto_ip_address {
   enum nabto_ip_address_type type;
   uint32_t specialProterty;
   union {
       struct nabto_ipv4_address v4;
       struct nabto_ipv6_address v6;
   };
};
```

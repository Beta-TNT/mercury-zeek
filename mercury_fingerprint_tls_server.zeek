# CISCO Mercyry TLS Fingerprint
# zeek version implemented by Beta-TNT

# mercury tls/tls server fingerprint
# ref:
# https://github.com/cisco/mercury/blob/main/python/pmercury/protocols/tls.py
# https://github.com/cisco/mercury/blob/main/python/pmercury/protocols/tls_server.py
# https://github.com/cisco/mercury/blob/main/python/pmercury/utils/tls_utils.py

module MercuryTlsServer;

# extension type code ref: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
const ext_data_extract: set[count] = {
    0x0001, 0x0005, 0x0007, 0x0008, # max_fragment_length, status_request, client_authz, server_authz
    0x0009, 0x000a, 0x000b, 0x000d, # cert_type, supported_groups, ec_point_formats, signature_algorithms
    0x000f, 0x0010, 0x0011, 0x0013, # heartbeat, application_layer_protocol_negotiation, status_request_v2, client_certificate_type
    0x0014, 0x0018, 0x001b, 0x001c, # server_certificate_type, token_binding, compress_certificate, record_size_limit
    0x002b, 0x002d, 0x0032, 0x5500  # supported_versions, psk_key_exchange_modes, signature_algorithms_cert, (prototype of TLS Token Binding)
};
# 0x5500 extension type code ref: https://success.qualys.com/discussions/s/question/0D52L00004TnvMESAZ/new-ie-sslhello-extension

const grease_single_int: set[count] = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 
    0xcaca, 0xdada, 0xeaea, 0xfafa
};

redef record connection += {
    mercury_tls_server_extensions: string &default="";
};

redef record SSL::Info += {
    mercury_tls_server:     string &optional &log;
};

function set_session(c: connection)
    {
    if ( ! c?$mercury_tls_server_extensions )
    	c$mercury_tls_server_extensions = "";
    }

function handle_extension_type_code(code: count)
    {
    if ( code in grease_single_int )
        code = 0x0a0a;
    }
	
event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
    {
    set_session(c);
    if ( c?$mercury_tls_server_extensions && |c$mercury_tls_server_extensions|>0 )
        c$ssl$mercury_tls_server = fmt("(%04x)(%04x)(%s)", version, cipher, c$mercury_tls_server_extensions);
    else
        c$ssl$mercury_tls_server = fmt("(%04x)(%04x)", version, cipher);
    }

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
    {
    if ( ! is_orig )
        {
        set_session(c);
        c$mercury_tls_server_extensions += fmt("(%04x", code);
        if ( code in ext_data_extract )
            c$mercury_tls_server_extensions += fmt("%04x", |val|) + bytestring_to_hexstr(val);
        c$mercury_tls_server_extensions += ")";
        }
    }

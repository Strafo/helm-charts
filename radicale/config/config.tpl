[server]
{{- if .Values.server.hosts -}}
hosts = {{ .Values.server.hosts }}
{{- end -}}
{{- if .Values.server.max_connections -}}
max_connections = {{ .Values.server.max_connections }}
{{- end -}}
{{- if .Values.server.max_content_length -}}
max_content_length = {{ .Values.server.max_content_length }}
{{- end -}}
{{- if .Values.server.timeout -}}
timeout = {{ .Values.server.timeout }}
{{- end -}}
{{- if .Values.server.ssl -}}
ssl = {{ .Values.server.ssl }}
{{- end -}}
{{- if .Values.server.certificate -}}
certificate = {{ .Values.server.certificate }}
{{- end -}}
{{- if .Values.server.key -}}
key = {{ .Values.server.key }}
{{- end -}}
{{- if .Values.server.certificate_authority -}}
certificate_authority = {{ .Values.server.certificate_authority }}
{{- end -}}
{{- if .Values.server.protocol -}}
protocol = {{ .Values.server.protocol }}
{{- end -}}
{{- if .Values.server.ciphersuite -}}
ciphersuite = {{ .Values.server.ciphersuite }}
{{- end -}}
{{- if .Values.server.script_name -}}
script_name = {{ .Values.server.script_name }}
{{- end -}}

[encoding]
{{- if .Values.encoding.request -}}
request = {{ .Values.encoding.request }}
{{- end -}}
{{- if .Values.encoding.stock -}}
stock = {{ .Values.encoding.stock }}
{{- end -}}

[auth]
{{- if .Values.auth.type -}}
type = {{ .Values.auth.type }}
{{- end -}}
{{- if .Values.auth.cache_logins -}}
cache_logins = {{ .Values.auth.cache_logins }}
{{- end -}}
{{- if .Values.auth.cache_successful_logins_expiry -}}
cache_successful_logins_expiry = {{ .Values.auth.cache_successful_logins_expiry }}
{{- end -}}
{{- if .Values.auth.cache_failed_logins_expiry -}}
cache_failed_logins_expiry = {{ .Values.auth.cache_failed_logins_expiry }}
{{- end -}}
{{- if .Values.auth.ldap_ignore_attribute_create_modify_timestamp -}}
ldap_ignore_attribute_create_modify_timestamp = {{ .Values.auth.ldap_ignore_attribute_create_modify_timestamp }}
{{- end -}}
{{- if .Values.auth.ldap_uri -}}
ldap_uri = {{ .Values.auth.ldap_uri }}
{{- end -}}
{{- if .Values.auth.ldap_base -}}
ldap_base = {{ .Values.auth.ldap_base }}
{{- end -}}
{{- if .Values.auth.ldap_reader_dn -}}
ldap_reader_dn = {{ .Values.auth.ldap_reader_dn }}
{{- end -}}
{{- if .Values.auth.ldap_secret -}}
ldap_secret = {{ .Values.auth.ldap_secret }}
{{- end -}}
{{- if .Values.auth.ldap_secret_file -}}
ldap_secret_file = {{ .Values.auth.ldap_secret_file }}
{{- end -}}
{{- if .Values.auth.ldap_groups_attribute -}}
ldap_groups_attribute = {{ .Values.auth.ldap_groups_attribute }}
{{- end -}}
{{- if .Values.auth.ldap_filter -}}
ldap_filter = {{ .Values.auth.ldap_filter }}
{{- end -}}
{{- if .Values.auth.ldap_user_attribute -}}
ldap_user_attribute = {{ .Values.auth.ldap_user_attribute }}
{{- end -}}
{{- if .Values.auth.ldap_use_ssl -}}
ldap_use_ssl = {{ .Values.auth.ldap_use_ssl }}
{{- end -}}
{{- if .Values.auth.ldap_security -}}
ldap_security = {{ .Values.auth.ldap_security }}
{{- end -}}
{{- if .Values.auth.ldap_ssl_verify_mode -}}
ldap_ssl_verify_mode = {{ .Values.auth.ldap_ssl_verify_mode }}
{{- end -}}
{{- if .Values.auth.ldap_ssl_ca_file -}}
ldap_ssl_ca_file = {{ .Values.auth.ldap_ssl_ca_file }}
{{- end -}}
{{- if .Values.auth.dovecot_connection_type -}}
dovecot_connection_type = {{ .Values.auth.dovecot_connection_type }}
{{- end -}}
{{- if .Values.auth.dovecot_socket -}}
dovecot_socket = {{ .Values.auth.dovecot_socket }}
{{- end -}}
{{- if .Values.auth.dovecot_host -}}
dovecot_host = {{ .Values.auth.dovecot_host }}
{{- end -}}
{{- if .Values.auth.dovecot_port -}}
dovecot_port = {{ .Values.auth.dovecot_port }}
{{- end -}}
{{- if .Values.auth.imap_host -}}
imap_host = {{ .Values.auth.imap_host }}
{{- end -}}
{{- if .Values.auth.imap_security -}}
imap_security = {{ .Values.auth.imap_security }}
{{- end -}}
{{- if .Values.auth.oauth2_token_endpoint -}}
oauth2_token_endpoint = {{ .Values.auth.oauth2_token_endpoint }}
{{- end -}}
{{- if .Values.auth.pam_serivce -}}
pam_serivce = {{ .Values.auth.pam_serivce }}
{{- end -}}
{{- if .Values.auth.pam_group_membership -}}
pam_group_membership = {{ .Values.auth.pam_group_membership }}
{{- end -}}
{{- if .Values.auth.htpasswd_filename -}}
htpasswd_filename = {{ .Values.auth.htpasswd_filename }}
{{- end -}}
{{- if .Values.auth.htpasswd_encryption -}}
htpasswd_encryption = {{ .Values.auth.htpasswd_encryption }}
{{- end -}}
{{- if .Values.auth.htpasswd_cache -}}
htpasswd_cache = {{ .Values.auth.htpasswd_cache }}
{{- end -}}
{{- if .Values.auth.delay -}}
delay = {{ .Values.auth.delay }}
{{- end -}}
{{- if .Values.auth.realm -}}
realm = {{ .Values.auth.realm }}
{{- end -}}
{{- if .Values.auth.lc_username -}}
lc_username = {{ .Values.auth.lc_username }}
{{- end -}}
{{- if .Values.auth.strip_domain -}}
strip_domain = {{ .Values.auth.strip_domain }}
{{- end -}}

[rights]
{{- if .Values.rights.type -}}
type = {{ .Values.rights.type }}
{{- end -}}
{{- if .Values.rights.file -}}
file = {{ .Values.rights.file }}
{{- end -}}
{{- if .Values.rights.permit_delete_collection -}}
permit_delete_collection = {{ .Values.rights.permit_delete_collection }}
{{- end -}}
{{- if .Values.rights.permit_overwrite_collection -}}
permit_overwrite_collection = {{ .Values.rights.permit_overwrite_collection }}
{{- end -}}
{{- if .Values.rights.urldecode_username -}}
urldecode_username = {{ .Values.rights.urldecode_username }}
{{- end -}}

[storage]
{{- if .Values.storage.type -}}
type = {{ .Values.storage.type }}
{{- end -}}
{{- if .Values.storage.filesystem_folder -}}
filesystem_folder = {{ .Values.storage.filesystem_folder }}
{{- end -}}
{{- if .Values.storage.filesystem_cache_folder -}}
filesystem_cache_folder = {{ .Values.storage.filesystem_cache_folder }}
{{- end -}}
{{- if .Values.storage.use_cache_subfolder_for_item -}}
use_cache_subfolder_for_item = {{ .Values.storage.use_cache_subfolder_for_item }}
{{- end -}}
{{- if .Values.storage.use_cache_subfolder_for_history -}}
use_cache_subfolder_for_history = {{ .Values.storage.use_cache_subfolder_for_history }}
{{- end -}}
{{- if .Values.storage.use_cache_subfolder_for_synctoken -}}
use_cache_subfolder_for_synctoken = {{ .Values.storage.use_cache_subfolder_for_synctoken }}
{{- end -}}
{{- if .Values.storage.use_mtime_and_size_for_item_cache -}}
use_mtime_and_size_for_item_cache = {{ .Values.storage.use_mtime_and_size_for_item_cache }}
{{- end -}}
{{- if .Values.storage.folder_umask -}}
folder_umask = {{ .Values.storage.folder_umask }}
{{- end -}}
{{- if .Values.storage.max_sync_token_age -}}
max_sync_token_age = {{ .Values.storage.max_sync_token_age }}
{{- end -}}
{{- if .Values.storage.skip_broken_item -}}
skip_broken_item = {{ .Values.storage.skip_broken_item }}
{{- end -}}
{{- if .Values.storage.hook -}}
hook = {{ .Values.storage.hook }}
{{- end -}}
{{- if .Values.storage.predefined_collections -}}
predefined_collections = {{ .Values.storage.predefined_collections | toPrettyJson }}
{{- end -}}

[web]
{{- if .Values.web.type -}}
type = {{ .Values.web.type }}
{{- end -}}

[logging]
{{- if .Values.logging.level -}}
level = {{ .Values.logging.level }}
{{- end -}}
{{- if .Values.logging.mask_passwords -}}
mask_passwords = {{ .Values.logging.mask_passwords }}
{{- end -}}
{{- if .Values.logging.bad_put_request_content -}}
bad_put_request_content = {{ .Values.logging.bad_put_request_content }}
{{- end -}}
{{- if .Values.logging.backtrace_on_debug -}}
backtrace_on_debug = {{ .Values.logging.backtrace_on_debug }}
{{- end -}}
{{- if .Values.logging.request_header_on_debug -}}
request_header_on_debug = {{ .Values.logging.request_header_on_debug }}
{{- end -}}
{{- if .Values.logging.request_content_on_debug -}}
request_content_on_debug = {{ .Values.logging.request_content_on_debug }}
{{- end -}}
{{- if .Values.logging.response_content_on_debug -}}
response_content_on_debug = {{ .Values.logging.response_content_on_debug }}
{{- end -}}
{{- if .Values.logging.rights_rule_doesnt_match_on_debug -}}
rights_rule_doesnt_match_on_debug = {{ .Values.logging.rights_rule_doesnt_match_on_debug }}
{{- end -}}
{{- if .Values.logging.storage_cache_actions_on_debug -}}
storage_cache_actions_on_debug = {{ .Values.logging.storage_cache_actions_on_debug }}
{{- end -}}

[headers]
{{- if .Values.headers.Access_Control_Allow_Origin -}}
Access-Control-Allow-Origin = {{ .Values.headers.Access_Control_Allow_Origin }}
{{- end -}}

[hook]
{{- if .Values.hook.type -}}
type = {{ .Values.hook.type }}
{{- end -}}
{{- if .Values.hook.rabbitmq_endpoint -}}
rabbitmq_endpoint = {{ .Values.hook.rabbitmq_endpoint }}
{{- end -}}
{{- if .Values.hook.rabbitmq_topic -}}
rabbitmq_topic = {{ .Values.hook.rabbitmq_topic }}
{{- end -}}
{{- if .Values.hook.rabbitmq_queue_type -}}
rabbitmq_queue_type = {{ .Values.hook.rabbitmq_queue_type }}
{{- end -}}

[reporting]
{{- if .Values.reporting.max_freebusy_occurrence -}}
max_freebusy_occurrence = {{ .Values.reporting.max_freebusy_occurrence }}
{{- end -}}

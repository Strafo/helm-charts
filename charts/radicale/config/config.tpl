[server]
{{- if .Values.config.server.hosts -}}
hosts = {{ .Values.config.server.hosts }}
{{- end -}}
{{- if .Values.config.server.max_connections -}}
max_connections = {{ .Values.config.server.max_connections }}
{{- end -}}
{{- if .Values.config.server.max_content_length -}}
max_content_length = {{ .Values.config.server.max_content_length }}
{{- end -}}
{{- if .Values.config.server.timeout -}}
timeout = {{ .Values.config.server.timeout }}
{{- end -}}
{{- if .Values.config.server.ssl -}}
ssl = {{ .Values.config.server.ssl }}
{{- end -}}
{{- if .Values.config.server.certificate -}}
certificate = {{ .Values.config.server.certificate }}
{{- end -}}
{{- if .Values.config.server.key -}}
key = {{ .Values.config.server.key }}
{{- end -}}
{{- if .Values.config.server.certificate_authority -}}
certificate_authority = {{ .Values.config.server.certificate_authority }}
{{- end -}}
{{- if .Values.config.server.protocol -}}
protocol = {{ .Values.config.server.protocol }}
{{- end -‍
{{- if .Values.config.server.ciphersuite -}}
ciphersuite = {{ .Values.config.server.ciphersuite }}
{{- end -}}
{{- if .Values.config.server.script_name -}}
script_name = {{ .Values.config.server.script_name }}
{{- end -}}

[encoding]
{{- if .Values.config.encoding.request -}}
request = {{ .Values.config.encoding.request }}
{{- end -}}
{{- if .Values.config.encoding.stock -}}
stock = {{ .Values.config.encoding.stock }}
{{- end -}}

[auth]
{{- if .Values.config.auth.type -}}
type = {{ .Values.config.auth.type }}
{{- end -}}
{{- if .Values.config.auth.cache_logins -}}
cache_logins = {{ .Values.config.auth.cache_logins }}
{{- end -}}
{{- if .Values.config.auth.cache_successful_logins_expiry -}}
cache_successful_logins_expiry = {{ .Values.config.auth.cache_successful_logins_expiry }}
{{- end -‍
{{- if .Values.config.auth.cache_failed_logins_expiry -}}
cache_failed_logins_expiry = {{ .Values.config.auth.cache_failed_logins_expiry }}
{{- end -}}
{{- if .Values.config.auth.ldap_ignore_attribute_create_modify_timestamp -}}
ldap_ignore_attribute_create_modify_timestamp = {{ .Values.config.auth.ldap_ignore_attribute_create_modify_timestamp }}
{{- end -}}
{{- if .Values.config.auth.ldap_uri -}}
ldap_uri = {{ .Values.config.auth.ldap_uri }}
{{- end -}}
{{- if .Values.config.auth.ldap_base -}}
ldap_base = {{ .Values.config.auth.ldap_base }}
{{- end -}}
{{- if .Values.config.auth.ldap_reader_dn -}}
ldap_reader_dn = {{ .Values.config.auth.ldap_reader_dn }}
{{- end -}}
{{- if .Values.config.auth.ldap_secret -}}
ldap_secret = {{ .Values.config.auth.ldap_secret }}
{{- end -}}
{{- if .Values.config.auth.ldap_secret_file -}}
ldap_secret_file = {{ .Values.config.auth.ldap_secret_file }}
{{- end -}}
{{- if .Values.config.auth.ldap_groups_attribute -}}
ldap_groups_attribute = {{ .Values.config.auth.ldap_groups_attribute }}
{{- end -}}
{{- if .Values.config.auth.ldap_filter -}}
ldap_filter = {{ .Values.config.auth.ldap_filter }}
{{- end -}}
{{- if .Values.config.auth.ldap_user_attribute -}}
ldap_user_attribute = {{ .Values.config.auth.ldap_user_attribute }}
{{- end -}}
{{- if .Values.config.auth.ldap_use_ssl -}}
ldap_use_ssl = {{ .Values.config.auth.ldap_use_ssl }}
{{- end -}}
{{- if .Values.config.auth.ldap_security -}}
ldap_security = {{ .Values.config.auth.ldap_security }}
{{- end -}}
{{- if .Values.config.auth.ldap_ssl_verify_mode -}}
ldap_ssl_verify_mode = {{ .Values.config.auth.ldap_ssl_verify_mode }}
{{- end -}}
{{- if .Values.config.auth.ldap_ssl_ca_file -}}
ldap_ssl_ca_file = {{ .Values.config.auth.ldap_ssl_ca_file }}
{{- end -}}
{{- if .Values.config.auth.dovecot_connection_type -}}
dovecot_connection_type = {{ .Values.config.auth.dovecot_connection_type }}
{{- end -}}
{{- if .Values.config.auth.dovecot_socket -}}
dovecot_socket = {{ .Values.config.auth.dovecot_socket }}
{{- end -}}
{{- if .Values.config.auth.dovecot_host -}}
dovecot_host = {{ .Values.config.auth.dovecot_host }}
{{- end -}}
{{- if .Values.config.auth.dovecot_port -}}
dovecot_port = {{ .Values.config.auth.dovecot_port }}
{{- end -}}
{{- if .Values.config.auth.imap_host -}}
imap_host = {{ .Values.config.auth.imap_host }}
{{- end -}}
{{- if .Values.config.auth.imap_security -}}
imap_security = {{ .Values.config.auth.imap_security }}
{{- end -}}
{{- if .Values.config.auth.oauth2_token_endpoint -}}
oauth2_token_endpoint = {{ .Values.config.auth.oauth2_token_endpoint }}
{{- end -}}
{{- if .Values.config.auth.pam_serivce -}}
pam_serivce = {{ .Values.config.auth.pam_serivce }}
{{- end -}}
{{- if .Values.config.auth.pam_group_membership -}}
pam_group_membership = {{ .Values.config.auth.pam_group_membership }}
{{- end -}}
{{- if .Values.config.auth.htpasswd_filename -}}
htpasswd_filename = {{ .Values.config.auth.htpasswd_filename }}
{{- end -}}
{{- if .Values.config.auth.htpasswd_encryption -}}
htpasswd_encryption = {{ .Values.config.auth.htpasswd_encryption }}
{{- end -}}
{{- if .Values.config.auth.htpasswd_cache -}}
htpasswd_cache = {{ .Values.config.auth.htpasswd_cache }}
{{- end -}}
{{- if .Values.config.auth.delay -}}
delay = {{ .Values.config.auth.delay }}
{{- end -}}
{{- if .Values.config.auth.realm -}}
realm = {{ .Values.config.auth.realm }}
{{- end -}}
{{- if .Values.config.auth.lc_username -}}
lc_username = {{ .Values.config.auth.lc_username }}
{{- end -}}
{{- if .Values.config.auth.strip_domain -}}
strip_domain = {{ .Values.config.auth.strip_domain }}
{{- end -}}

[rights]
{{- if .Values.config.rights.type -}}
type = {{ .Values.config.rights.type }}
{{- end -}}
{{- if .Values.config.rights.file -}}
file = {{ .Values.config.rights.file }}
{{- end -}}
{{- if .Values.config.rights.permit_delete_collection -}}
permit_delete_collection = {{ .Values.config.rights.permit_delete_collection }}
{{- end -}}
{{- if .Values.config.rights.permit_overwrite_collection -}}
permit_overwrite_collection = {{ .Values.config.rights.permit_overwrite_collection }}
{{- end -}}
{{- if .Values.config.rights.urldecode_username -}}
urldecode_username = {{ .Values.config.rights.urldecode_username }}
{{- end -}}

[storage]
{{- if .Values.config.storage.type -}}
type = {{ .Values.config.storage.type }}
{{- end -}}
{{- if .Values.config.storage.filesystem_folder -}}
filesystem_folder = {{ .Values.config.storage.filesystem_folder }}
{{- end -}}
{{- if .Values.config.storage.filesystem_cache_folder -}}
filesystem_cache_folder = {{ .Values.config.storage.filesystem_cache_folder }}
{{- end -}}
{{- if .Values.config.storage.use_cache_subfolder_for_item -}}
use_cache_subfolder_for_item = {{ .Values.config.storage.use_cache_subfolder_for_item }}
{{- end -}}
{{- if .Values.config.storage.use_cache_subfolder_for_history -}}
use_cache_subfolder_for_history = {{ .Values.config.storage.use_cache_subfolder_for_history }}
{{- end -}}
{{- if .Values.config.storage.use_cache_subfolder_for_synctoken -}}
use_cache_subfolder_for_synctoken = {{ .Values.config.storage.use_cache_subfolder_for_synctoken }}
{{- end -}}
{{- if .Values.config.storage.use_mtime_and_size_for_item_cache -}}
use_mtime_and_size_for_item_cache = {{ .Values.config.storage.use_mtime_and_size_for_item_cache }}
{{- end -}}
{{- if .Values.config.storage.folder_umask -}}
folder_umask = {{ .Values.config.storage.folder_umask }}
{{- end -}}
{{- if .Values.config.storage.max_sync_token_age -}}
max_sync_token_age = {{ .Values.config.storage.max_sync_token_age }}
{{- end -}}
{{- if .Values.config.storage.skip_broken_item -}}
skip_broken_item = {{ .Values.config.storage.skip_broken_item }}
{{- end -}}
{{- if .Values.config.storage.hook -}}
hook = {{ .Values.config.storage.hook }}
{{- end -}}
{{- if .Values.config.storage.predefined_collections -}}
predefined_collections = {{ .Values.config.storage.predefined_collections | toPrettyJson }}
{{- end -}}

[web]
{{- if .Values.config.web.type -}}
type = {{ .Values.config.web.type }}
{{- end -}}

[logging]
{{- if .Values.config.logging.level -}}
level = {{ .Values.config.logging.level }}
{{- end -}}
{{- if .Values.config.logging.mask_passwords -}}
mask_passwords = {{ .Values.config.logging.mask_passwords }}
{{- end -}}
{{- if .Values.config.logging.bad_put_request_content -}}
bad_put_request_content = {{ .Values.config.logging.bad_put_request_content }}
{{- end -}}
{{- if .Values.config.logging.backtrace_on_debug -}}
backtrace_on_debug = {{ .Values.config.logging.backtrace_on_debug }}
{{- end -}}
{{- if .Values.config.logging.request_header_on_debug -}}
request_header_on_debug = {{ .Values.config.logging.request_header_on_debug }}
{{- end -}}
{{- if .Values.config.logging.request_content_on_debug -}}
request_content_on_debug = {{ .Values.config.logging.request_content_on_debug }}
{{- end -}}
{{- if .Values.config.logging.response_content_on_debug -}}
response_content_on_debug = {{ .Values.config.logging.response_content_on_debug }}
{{- end -}}
{{- if .Values.config.logging.rights_rule_doesnt_match_on_debug -}}
rights_rule_doesnt_match_on_debug = {{ .Values.config.logging.rights_rule_doesnt_match_on_debug }}
{{- end -}}
{{- if .Values.config.logging.storage_cache_actions_on_debug -}}
storage_cache_actions_on_debug = {{ .Values.config.logging.storage_cache_actions_on_debug }}
{{- end -}}

[headers]
{{- if .Values.config.headers.Access_Control_Allow_Origin -}}
Access-Control-Allow-Origin = {{ .Values.config.headers.Access_Control_Allow_Origin }}
{{- end -}}

[hook]
{{- if .Values.config.hook.type -}}
type = {{ .Values.config.hook.type }}
{{- end -}}
{{- if .Values.config.hook.rabbitmq_endpoint -}}
rabbitmq_endpoint = {{ .Values.config.hook.rabbitmq_endpoint }}
{{- end -}}
{{- if .Values.config.hook.rabbitmq_topic -}}
rabbitmq_topic = {{ .Values.config.hook.rabbitmq_topic }}
{{- end -}}
{{- if .Values.config.hook.rabbitmq_queue_type -}}
rabbitmq_queue_type = {{ .Values.config.hook.rabbitmq_queue_type }}
{{- end -}}

[reporting]
{{- if .Values.config.reporting.max_freebusy_occurrence -}}
max_freebusy_occurrence = {{ .Values.config.reporting.max_freebusy_occurrence }}
{{- end -}}
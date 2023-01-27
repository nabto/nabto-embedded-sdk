#include "tcp_tunnel_services.h"

#include <apps/common/json_config.h>

#include <stdlib.h>
#include <string.h>

static bool load_services_from_json(struct nn_vector* services, cJSON* json, struct nn_log* logger);
static struct tcp_tunnel_service* service_from_json(cJSON* json, struct nn_log* logger);

static const char* LOGM = "services";

struct tcp_tunnel_service* tcp_tunnel_service_new()
{
    struct tcp_tunnel_service* service = calloc(1, sizeof(struct tcp_tunnel_service));
    if (service == NULL) {
        return service;
    }
    nn_string_map_init(&service->metadata, get_default_allocator());
    return service;
}

void tcp_tunnel_service_free(struct tcp_tunnel_service* service)
{
    free(service->id);
    free(service->type);
    free(service->host);
    nn_string_map_deinit(&service->metadata);
    free(service);
}

bool load_tcp_tunnel_services(struct nn_vector* services, struct nm_fs* fsImpl, const char* servicesFile, struct nn_log* logger)
{
    if (!json_config_exists(fsImpl, servicesFile)) {
        if (!tcp_tunnel_create_default_services_file(fsImpl, servicesFile)) {
            NN_LOG_ERROR(logger, LOGM, "Cannot create default services file");
            return false;
        }
    }

    cJSON* config;
    if (!json_config_load(fsImpl, servicesFile, &config, logger)) {
        return false;
    }


    if (!load_services_from_json(services, config, logger)) {
        NN_LOG_ERROR(logger, LOGM, "Cannot parse services from json. Use this format: [ {\"Id\": \"...\", \"Type\": \"...\", \"Host\": \"...\", \"Port\": 4242 } ]");
        return false;
    }

    cJSON_Delete(config);

    return true;
}

bool load_services_from_json(struct nn_vector* services, cJSON* json, struct nn_log* logger)
{
    if (!cJSON_IsArray(json)) {
        NN_LOG_ERROR(logger, LOGM, "The configuration needs to be an array of services");
        return false;
    }

    size_t items = cJSON_GetArraySize(json);
    for (size_t i = 0; i < items; i++) {
        cJSON* service = cJSON_GetArrayItem(json, (int)i);
        struct tcp_tunnel_service* s = service_from_json(service, logger);
        if (s) {
            nn_vector_push_back(services, &s);
        } else {
            return false;
        }
    }
    return true;
}

struct tcp_tunnel_service* service_from_json(cJSON* json, struct nn_log* logger)
{
    if (cJSON_IsObject(json)) {
        cJSON* id = cJSON_GetObjectItem(json, "Id");
        cJSON* type = cJSON_GetObjectItem(json, "Type");
        cJSON* host = cJSON_GetObjectItem(json, "Host");
        cJSON* port = cJSON_GetObjectItem(json, "Port");

        if (cJSON_IsString(id) &&
            cJSON_IsString(type) &&
            cJSON_IsString(host) &&
            cJSON_IsNumber(port))
        {
            struct tcp_tunnel_service* service = tcp_tunnel_service_new();
            if (service == NULL) {
                return NULL;
            }
            service->id = strdup(id->valuestring);
            service->type = strdup(type->valuestring);
            service->host = strdup(host->valuestring);
            service->port = (uint16_t)port->valuedouble;

            cJSON* metadata = cJSON_GetObjectItem(json, "Metadata");
            if (cJSON_IsObject(metadata))
            {
                cJSON* metadata_entry = NULL;
                cJSON_ArrayForEach(metadata_entry, metadata)
                {
                    const char* key = metadata_entry->string;

                    if (!cJSON_IsString(metadata_entry))
                    {
                        NN_LOG_WARN(logger, LOGM, "Service %s has a non-string metadata value for key %s", service->id, key);
                        continue;
                    }

                    const char* value = metadata_entry->valuestring;
                    nn_string_map_insert(&service->metadata, key, value);
                }
            }

            return service;
        }
    }
    NN_LOG_ERROR(logger, LOGM, "Invalid service definition. Missing one of Id, Type, Host or Port");
    return NULL;
}


cJSON* tcp_tunnel_service_as_json(struct tcp_tunnel_service* service)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "Id", cJSON_CreateString(service->id));
    cJSON_AddItemToObject(root, "Type", cJSON_CreateString(service->type));
    cJSON_AddItemToObject(root, "Host", cJSON_CreateString(service->host));
    cJSON_AddItemToObject(root, "Port", cJSON_CreateNumber(service->port));

    cJSON* metadata = cJSON_CreateObject();
    struct nn_string_map_iterator it;
    NN_STRING_MAP_FOREACH(it, &service->metadata)
    {
        const char* key = nn_string_map_key(&it);
        const char* value = nn_string_map_value(&it);
        cJSON_AddItemToObject(metadata, key, cJSON_CreateString(value));
    }

    cJSON_AddItemToObject(root, "Metadata", metadata);

    return root;
}

bool tcp_tunnel_create_default_services_file(struct nm_fs* fsImpl, const char* servicesFile)
{
    cJSON* root = cJSON_CreateArray();
    if (root == NULL) {
        return false;
    }

    struct tcp_tunnel_service* ssh = tcp_tunnel_service_new();
    if (ssh == NULL) {
        return false;
    }

    ssh->id   = strdup("ssh");
    ssh->type = strdup("ssh");
    ssh->host = strdup("127.0.0.1");
    ssh->port = 22;

    cJSON_AddItemToArray(root, tcp_tunnel_service_as_json(ssh));
    tcp_tunnel_service_free(ssh);
    return json_config_save(fsImpl, servicesFile, root);
}

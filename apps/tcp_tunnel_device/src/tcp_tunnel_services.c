#include "tcp_tunnel_services.h"

#include <apps/common/json_config.h>

#include <cjson/cJSON.h>

#include <stdlib.h>

static bool create_default_services_file(const char* servicesFile);
static bool load_services_from_json(struct np_vector* services, cJSON* json);
static struct tcp_tunnel_service* service_from_json(cJSON* json);

struct tcp_tunnel_service* tcp_tunnel_service_new()
{
    struct tcp_tunnel_service* service = calloc(1, sizeof(struct tcp_tunnel_service));
    return service;
}

void tcp_tunnel_service_free(struct tcp_tunnel_service* service)
{
    free(service->id);
    free(service->type);
    free(service->host);
    free(service);
}

bool load_tcp_tunnel_services(struct np_vector* services, const char* servicesFile, const char** errorText)
{
    if (!json_config_exists(servicesFile)) {
        if (!create_default_services_file(servicesFile)) {
            *errorText = "Cannot create default services file";
            return false;
        }
    }

    cJSON* config;
    if (!json_config_load(servicesFile, &config)) {
        *errorText = "Cannot load services fom file";
        return false;
    }


    if (!load_services_from_json(services, config)) {
        *errorText = "Cannot parse services from json";
        return false;
    }

    return true;
}

bool load_services_from_json(struct np_vector* services, cJSON* json)
{
    if (!cJSON_IsArray(json)) {
        return false;
    }

    size_t items = cJSON_GetArraySize(json);
    for (size_t i = 0; i < items; i++) {
        cJSON* service = cJSON_GetArrayItem(json, i);
        struct tcp_tunnel_service* s = service_from_json(service);
        if (s) {
            np_vector_push_back(services, s);
        }
    }
    return true;
}

struct tcp_tunnel_service* service_from_json(cJSON* json)
{
    if (!cJSON_IsObject(json)) {
        return NULL;
    }
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
        service->id = strdup(id->valuestring);
        service->type = strdup(type->valuestring);
        service->host = strdup(host->valuestring);
        service->port = (uint16_t)port->valuedouble;
        return service;
    } else {
        return NULL;
    }
}


cJSON* service_as_json(struct tcp_tunnel_service* service)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "Id", cJSON_CreateString(service->id));
    cJSON_AddItemToObject(root, "Type", cJSON_CreateString(service->type));
    cJSON_AddItemToObject(root, "Host", cJSON_CreateString(service->host));
    cJSON_AddItemToObject(root, "Port", cJSON_CreateNumber(service->port));
    return root;
}

bool create_default_services_file(const char* servicesFile)
{
    cJSON* root = cJSON_CreateArray();

    struct tcp_tunnel_service ssh;

    ssh.id = "ssh";
    ssh.type = "ssh";
    ssh.host = "127.0.0.1";
    ssh.port = 22;

    cJSON_AddItemToArray(root, service_as_json(&ssh));

    return json_config_save(servicesFile, root);
}

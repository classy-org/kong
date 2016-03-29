local utils = require "kong.tools.utils"
local stringy = require "stringy"
local url = require("socket.url")

local function generate_if_missing(v, t, column)
  if not v or stringy.strip(v) == "" then
    return true, nil, { [column] = utils.random_string()}
  end
  return true
end

local function generate_refresh_token(v, t, column)
  if t.expires_in and t.expires_in > 0 then
    return generate_if_missing(v, t, column)
  end
  return true
end

local function validate_uris(v, t, column)
  if v and type(v) == "table" then
    for _, uri in ipairs(v) do
      local parsed_uri = url.parse(uri)
      if not (parsed_uri and parsed_uri.host and parsed_uri.scheme) then
        return false, "cannot parse '"..uri.."'"
      end
      if parsed_uri.fragment ~= nil then
        return false, "fragment not allowed in '"..uri.."'"
      end
    end
  end
  return true, nil
end

local OAUTH2_CREDENTIALS_SCHEMA = {
  primary_key = {"id"},
  table = "oauth2_credentials",
  fields = {
    id = { type = "id", dao_insert_value = true },
    consumer_id = { type = "id", required = true, foreign = "consumers:id" },
    name = { type = "string", required = true },
    client_id = { type = "string", required = false, unique = true, func = generate_if_missing },
    client_secret = { type = "string", required = false, unique = true, func = generate_if_missing },
    redirect_uri = { type = "array", func = validate_uris, required = true },
    created_at = { type = "timestamp", immutable = true, dao_insert_value = true }
  },
  marshall_event = function(self, t)
    return { id = t.id, consumer_id = t.consumer_id, client_id = t.client_id }
  end
}

local OAUTH2_AUTHORIZATION_CODES_SCHEMA = {
  primary_key = {"id"},
  table = "oauth2_authorization_codes",
  fields = {
    id = { type = "id", dao_insert_value = true },
    code = { type = "string", required = false, unique = true, immutable = true, func = generate_if_missing },
    authenticated_userid = { type = "string", required = false },
    scope = { type = "string" },
    created_at = { type = "timestamp", immutable = true, dao_insert_value = true }
  }
}

local BEARER = "bearer"
local OAUTH2_TOKENS_SCHEMA = {
  primary_key = {"id"},
  table = "oauth2_tokens",
  fields = {
    id = { type = "id", dao_insert_value = true },
    credential_id = { type = "id", required = true, foreign = "oauth2_credentials:id" },
    token_type = { type = "string", required = true, enum = { BEARER }, default = BEARER },
    expires_in = { type = "number", required = true },
    access_token = { type = "string", required = false, unique = true, func = generate_if_missing },
    refresh_token = { type = "string", required = false, unique = true },
    authenticated_userid = { type = "string", required = false },
    scope = { type = "string" },
    created_at = { type = "timestamp", immutable = true, dao_insert_value = true }
  },
  marshall_event = function(self, t)
    return { id = t.id, credential_id = t.credential_id, access_token = t.access_token }
  end
}

-- @override
--function OAuth2Credentials:_marshall(t)
--  if type(t.redirect_uri) == "table" then
--    t.redirect_uri = cjson.encode(t.redirect_uri)
--  elseif type(t.redirect_uri) == "string" then
--    t.redirect_uri = "{"..t.redirect_uri.."}"
--  end
--  return t
--end

-- @override
--function OAuth2Credentials:_unmarshall(t)
  -- deserialize configs (tables) string to json
--  if type(t.redirect_uri) == "string" then
--    local success, result = pcall(cjson.decode, t.redirect_uri);
--    if success then
--      t.redirect_uri = result
--    else
      -- this record was created before redirect_uri was saved as an array.
--      local legacy_redirect_uri = t.redirect_uri
--      t.redirect_uri = {}
--      t.redirect_uri[1] = legacy_redirect_uri
--    end
--  end
--  return t
--end

return {
  oauth2_credentials = OAUTH2_CREDENTIALS_SCHEMA,
  oauth2_authorization_codes = OAUTH2_AUTHORIZATION_CODES_SCHEMA,
  oauth2_tokens = OAUTH2_TOKENS_SCHEMA
}

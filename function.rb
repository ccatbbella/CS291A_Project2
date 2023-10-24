# frozen_string_literal: true
require 'time'
require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  http_method = event['httpMethod']
  if http_method != 'GET' && http_method != 'POST'
    return response(body: 'Method Not Allowed', status: 405)
  end

  path = event['path']
  if path != '/' && path != '/token'
    return response(status: 404, body: 'Not Found')
  end

  if (http_method == 'GET' && path != '/') || (http_method == 'POST' && path != '/token')
    return response(body: 'Method Not Allowed', status: 405)
  end

  # can handle mix case keys
  event['headers'] = event['headers'].transform_keys(&:downcase)

  if http_method == 'GET' && event['path'] == '/'
    authorization_header = event['headers']['authorization']
    if !authorization_header || authorization_header == ""
      return response(status: 403, body: 'Forbidden: Proper Authorization header required')
    end
    parts = authorization_header.split(" ")
    if parts[0] != "Bearer"
      return response(status: 403, body: 'Forbidden: Proper Authorization header required')
    end

    # Validate JWT token
    token = authorization_header.sub('Bearer ', '')
    begin
      decoded_token = JWT.decode(token, key=ENV['JWT_SECRET'], algorithms='HS256')
    rescue JWT::ExpiredSignature
      return response(status: 401, body: 'Unauthorized: Token is expired')
    rescue JWT::ImmatureSignature
      return response(status: 401, body: 'Unauthorized: Token is not yet valid')
    rescue JWT::DecodeError
      return response(status: 403, body: 'Unauthorized: Invalid token')
    end

    data = decoded_token[0]['data']
    return response(status: 200, body: data)
  end

  if http_method == 'POST' && event['path'] == '/token'
    content_type = event['headers']['content-type']
    if content_type != 'application/json'
      return response(status: 415, body: 'Unsupported Media Type: Content-Type must be application/json')
    end

    request_body = event['body']
    begin
      json_body = JSON.parse(request_body)
      payload = {
        'data' => json_body,
        'exp' => (Time.now.to_i + 5), # 5 seconds from the current time
        'nbf' => (Time.now.to_i + 2) # 2 seconds from the current time
      }
      # Generate the JWT token using HS256
      jwt_token = JWT.encode(payload, ENV['JWT_SECRET'], 'HS256')
      response_json = { 'token' => jwt_token }
      return response(status: 201, body: response_json)
    rescue
      return response(status: 422, body: 'Unprocessable Entity: Request body is not valid JSON')
    end
  end
end

def response(body: nil, status: 200)
{
  body: body ? body.to_json + "\n" : '',
  statusCode: status
}
end

if $PROGRAM_NAME == __FILE__
# If you run this file directly via `ruby function.rb` the following code
# will execute. You can use the code below to help you test your functions
# without needing to deploy first.
ENV['JWT_SECRET'] = 'NOTASECRET'

# Call /token
PP.pp main(context: {}, event: {
             'body' => '{"name": "bboe"}',
             'headers' => { 'Content-Type' => 'application/json' },
             'httpMethod' => 'POST',
             'path' => '/token'
           })

# Generate a token
payload = {
  data: { user_id: 128 },
  exp: Time.now.to_i + 1,
  nbf: Time.now.to_i
}
token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
# Call /
PP.pp main(context: {}, event: {
             'headers' => { 'Authorization' => "Bearer #{token}",
                            'Content-Type' => 'application/json' },
             'httpMethod' => 'GET',
             'path' => '/'
           })

payload = {
  data: { user_id: 111 },
  exp: Time.now.to_i + 1,
  nbf: Time.now.to_i
}
token = JWT.encode(payload, nil, 'none')
PP.pp main(context: {}, event: {
             'headers' => { 'Authorization' => "Bearer #{token}",
                            'Content-Type' => 'application/json' },
             'httpMethod' => 'GET',
             'path' => '/'
           })
end

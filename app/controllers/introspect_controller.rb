class IntrospectController < ApplicationController
  before_filter :require_user_access_token

  rescue_from FbGraph::Exception, Rack::OAuth2::Client::Error do |e|
    provider = case e
    when FbGraph::Exception
      'Facebook'
    when Rack::OAuth2::Client::Error
      'Google'
    end
    raise Rack::OAuth2::Server::Resource::Bearer::BadRequest.new(
      :invalid_request, [
        "Your access token is valid, but we failed to fetch profile data from #{provider}.",
        "#{provider}'s access token on our side seems expired/revoked."
      ].join(' ')
    )
  end

  def show
    #:TODO: access token MUST be valid because this controller is running.

    is_valid=true
    sub =""
    meta = {}
    if params[:token_type_hint] == "id_token"

        id_token = IdToken.find(:first, :conditions =>[
            "account_id = ? and client_id = ?",
                current_token.account_id, current_token.client_id ])
        
        decoded_id_token= IdToken.decode( params[:token] )
        is_valid = id_token.nonce == decoded_id_token.nonce
        
        #:TODO: check if ID Token parameters are all valid.
        #:TODO: check if ID Token has been timed out.

        meta['sub'] =  decoded_id_token.sub #:TODO:
    else
        #:TODO: access token  validation
        ppid = current_token.account
                .pairwise_pseudonymous_identifiers
                    .find_by_sector_identifier(
                        current_token.client.sector_identifier)
        meta['sub'] = ppid.identifier
    end        

    render json: meta.merge( { 'valid' => is_valid,
                       'exp' => current_token.expires_at.to_i,
                       'iad' => current_token.created_at.to_i, 
                       'scope' =>  current_token.scopes.map{|scope|scope.name}.join(' '), 
                       'client_id' => current_token.client.identifier,  #:TODO:
                       'aud' =>  [ current_token.client.identifier, ], #:TODO:
                      })
  end

  private

  def required_scopes
    Scope::OPENID
  end
end

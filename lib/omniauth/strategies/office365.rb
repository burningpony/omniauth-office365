require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Office365 < OmniAuth::Strategies::OAuth2
      BASE_SCOPE_URL = 'https://graph.windows.net/'
      BASE_SCOPES = %w(openid offline_access)
      DEFAULT_SCOPE = 'openid offline_access'
      option :name, :office365

      option :client_options, site:          'https://login.microsoftonline.com',
                              token_url:     '/common/oauth2/v2.0/token',
                              authorize_url: '/common/oauth2/v2.0/authorize'

      def authorize_params
        super.tap do |params|
          raw_scope = params[:scope] || DEFAULT_SCOPE
          scope_list = raw_scope.split(' ').map { |item| item.split(',') }.flatten
          scope_list.map! { |s| s =~ /^https?:\/\// || BASE_SCOPES.include?(s) ? s : "#{BASE_SCOPE_URL}#{s}" }
          params[:scope] = scope_list.join(' ')

          params[:response_type] = 'code' if params[:response_type].nil?
          params[:response_mode] = 'query' if params[:response_mode].nil?

          session['omniauth.state'] = params[:state] if params['state']
        end
      end

      uid do
        raw_info['sub']
      end

      info do
        {
          name: raw_info['name'],
          email: raw_info['preferred_username'],
          oid: raw_info['oid']
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        # it's all here in JWT http://msdn.microsoft.com/en-us/library/azure/dn195587.aspx
        @raw_info ||= ::JWT.decode(access_token['id_token'], nil, false).first
      end
    end
  end
end

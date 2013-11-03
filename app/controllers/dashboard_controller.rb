class DashboardController < ApplicationController
  before_filter :require_authentication

  def show
    @clients = current_account.clients
    @authorizations = current_account.authorizations
  end
end

class User < ActiveRecord::Base
  attr_reader :password
  validates :username, :email, :password_digest, presence: true
  validates :password, length: { minimum: 6 }, allow_nil: true
  validates :access_level, inclusion: { in: %w(member general) }
  after_initialize :ensure_access_level, :ensure_session_token
  def self.generate_token
    SecureRandom.urlsafe_base64
  end

  def self.find_by_credentials(email, password)
    found_user = User.find_by_email(email)
    return nil unless found_user
    if found_user.is_password?(password)
      found_user
    else
      nil
    end
  end

  def ensure_session_token
    self.session_token ||= User.generate_token
  end

  def ensure_access_level
    self.access_level ||= "general"
  end

  def is_password?(password)
    BCrypt::Password.new(self.password_digest).is_password?(password)
  end

  def password=(password)
    self.password_digest = BCrypt::Password.create(password)
    @password            = password
  end

  def reset_session_token!
    self.update!(session_token: User.generate_token)
    self.session_token
  end
end

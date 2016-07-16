class User < ApplicationRecord
    has_many :microposts, dependent: :destroy
    #Association to follower another user
    has_many :active_relationships, class_name: "Relationship",
                                    foreign_key: "follower_id",
                                    dependent: :destroy
    #Association to see who this user is being followed by
    has_many :passive_relationships, class_name: "Relationship",
                                    foreign_key: "followed_id",
                                    dependent: :destroy
    #Association to see who a user is following
    has_many :following, through: :active_relationships, source: :followed
    #Association to see who are a user's followers
    has_many :followers, through: :passive_relationships, source: :follower
    attr_accessor :remember_token, :activation_token, :reset_token
    before_save :downcase_email
    before_create :create_activation_digset
    
    validates :name, presence: true, length: {maximum: 50 }
    VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
    validates :email, presence: true, length: {maximum: 255 }, 
    format: {with: VALID_EMAIL_REGEX},
    uniqueness: { case_sensitive: false }
    has_secure_password
    validates :password, presence: true, length: { minimum: 6 }, allow_nil: true
    #password must have one special character and number
    
    
# Returns the hash digest of the given string.
  def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end

# Creates a token for a given user
  def User.new_token
    SecureRandom.urlsafe_base64
  end
  
# Creates and saves a remember token for a given user for use in persistent sessions after browser close
  def remember
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
  end
  
  def forget
    update_attribute(:remember_digest, nil)
  end
  
# Returns true if the given token matches the digest.
  def authenticated?(attribute, token)
    digest = send("#{attribute}_digest")
    return false if digest.nil? 
    BCrypt::Password.new(digest).is_password?(token)
  end


 #Activates an Account
 def activate
  update_columns(activated: true, activated_at: Time.zone.now)
 end
 #Sends Activation Email
 def send_activation_email
   UserMailer.account_activation(self).deliver_now
 end 
 
 
  #Creates Password Reset Digest for a given user
  def create_reset_digest
    self.reset_token = User.new_token
    update_columns(reset_digest: User.digest(reset_token), reset_sent_at: Time.zone.now )
  end
 
 #Sends Password Reset Email to a given user
 def send_password_reset_email
   UserMailer.password_reset(self).deliver_now
 end
 
 def password_reset_expired?
   reset_sent_at < 2.hours.ago
 end
 
  #Feed on user's homepage
  def feed
    following_ids = "SELECT followed_id FROM relationships
                     WHERE  follower_id = :user_id"
    Micropost.where("user_id IN (#{following_ids})
                     OR user_id = :user_id", user_id: id)
  end
  
  # Follows a user.
  def follow(other_user)
    active_relationships.create(followed_id: other_user.id)
  end
 
 # Unfollows a user.
  def unfollow(other_user)
    active_relationships.find_by(followed_id: other_user.id).destroy
  end
  
  # Returns true if user is following another user
  def following?(other_user)
    following.include?(other_user)
  end

  private
    #Converts email to all lower case
    def downcase_email
       self.email = email.downcase
    end
   
   #Creates and assigns the activation token and digest
   def create_activation_digset
     self.activation_token = User.new_token
     self.activation_digest = User.digest(activation_token)
   end
end





class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  validates_presence_of :email, :first_name, :last_name, :password, on: :create
  validates :email, uniqueness: true # why not 'validates_uniqueness_of'?
end

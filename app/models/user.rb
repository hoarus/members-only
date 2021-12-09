class User < ApplicationRecord
  validates :password, length: { in: 6..16 }, presence: true
  validates :username, length: { in: 4..12 }, presence: true, uniqueness: true
  validates :email, presence: true, uniqueness: true

  has_many :posts, dependent: :destroy
end

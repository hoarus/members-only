class Post < ApplicationRecord
  validates :title, length: { in: 4..30 }, presence: true
  validates :body, presence: true
  validates :user_id, presence: true

  belongs_to :user
end

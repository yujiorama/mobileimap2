# -*- coding: utf-8 -*-
require 'gmail'
require 'kconv'

class GmailClient

  def initialize(*av)
    @gmail = Gmail.new(*av)
  end

  def list_new_mail
    @gmail.inbox.mails(:unseen).map do |mail|
      body =''
      if mail.multipart?
        mail.parts.each do |part|
          body = part.decoded.toutf8 if /^text\/plain;/ =~ part.content_type
        end
      else
        body = mail.body.decoded.toutf8
      end

      # XXX: 既読フラグを落とす
      mail.mark(:unread)
      {
        :message_id => mail.message_id,
        :subject    => mail.subject ? mail.subject.toutf8 : 'no subject',
        :body       => body,
      }
    end
  end
end



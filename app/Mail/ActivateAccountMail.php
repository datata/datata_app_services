<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class ActivateAccountMail extends Mailable
{
    use Queueable, SerializesModels;

    protected string $name;
    protected string $emailUser;
    protected string $hash;
    protected string $appUrl;

    /**
     * Create a new message instance.
     *
     * @return void
     */
    public function __construct(string $name, string $emailUser, string $hash, string $appUrl)
    {
        $this->name = $name;
        $this->email = $emailUser;
        $this->hash = $hash;
        $this->app_url = $appUrl;
    }

    /**
     * Build the message.
     *
     * @return $this
     */
    public function build()
    {
        $dataMail = $this->activateUrl();

        return $this->from(env('MAIL_FROM_ADDRESS'))->view('welcome', $dataMail);
    }

    
    private function toArray(): array
    {
        return [
            'hash' => $this->hash,
            'email_user' => str_replace('@', '[at]', $this->email),
            'app_url' => $this->app_url
        ];
    }

    private function activateUrl()
    {
        return [
            'activate_url' => $this->app_url.'/api/verify-account/?hash='.$this->hash."&email=".str_replace('@', '[at]', $this->email)
        ];
    }
}

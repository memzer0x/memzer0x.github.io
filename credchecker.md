# Credchecker
Credchecker is the first challenge of the Flare-On 8 (2021) CTF Event and it was super easy to complete.

## The Challenge
We are given a **admin.html** file (which is the challenge meat), and a **img** directory containing an image (not important to us).

I first start a **PHP Web Server** using the following command
`php -S 127.0.0.1:6969`

Then i can access the challenge using my browser at the following URL **127.0.0.1:6969**, let's see what the challenge page looks like in the first place.

![admin.html](https://i.imgur.com/CXojMs8.png)

## Source Code
To solve the challenge we need to look at the javascript code inside the **admin.html** file.

Whenever the button is pressed, the **checkCreds()** javascript function gets called.

![button](https://i.imgur.com/NVGdHtC.png)

Let's find this **checkCreds()** function.

![checkCreds](https://i.imgur.com/Y4OnfT7.png)

We're basically checking if **btoa(ourInput)** is equal to **goldenticket**, the **btoa** function takes a base64 string and decodes it.

We can assume that the password is the the base64 encoded verson of **goldenticket**, or **atob("goldenticket")** should also print you the password, the **atob** function takes an ascii string and encode it into base64.

Let's prove the password works...

![goldenticket](https://i.imgur.com/IP0qiPa.png)

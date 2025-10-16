- first after installing the server and running it we start making and setting up the environment of the server in the .env file 
- what we do in the .env file is that we declare the new variables ( access-token-secrets and refresh-token-secrets ) which we will be using to secure our server
- what we will do with the .env setup is we are going to replace every (**secret variable**) which ate insecure with the secure value of (**access-token-access**) 
- the value of the access token with be generated using the following ( 
   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
- but before this we need to steup our server to use the .env file using the following (require('dotenv').config();
  if (!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
  console.error("Missing secrets in .env — copy .env.example -> .env and set secrets");
  process.exit(1); }  ) this will allow to use the variables we setup
- now we start looking for the insecure code that uses the value secret and replace it with the secure toke we obtained ![[Pasted image 20251016211705.png]]
- now we ensure that our code in server.js is working and accessing the code the variables we made and we do that by adding a function for each to check for the value of the token (helper functions)
- now we stat to enforce and declare the issuer and the audience tokens (iss,aud) and the algorithm used so now when signing a token and decoding it the algorithm will show (**hs256**)and then we checking with a wrong token we face the error json web token error or token expired error for the 10 limit we have had setup in the .env file
- and now for the new refresh mechanism we make  it using a refresh token variable where it stores the access token as an id in the data base where each id is unique such that when the serve is refreshed no token will used twice ![[Pasted image 20251016224635.png]]
- and now as we start to test our code and edits we make a file and name it weak.js where it will try to bypass the server and it will bypass the original secure code and access and return a 200 ok  by sending a token to the endpoint but after the hardening it will return a 401 invalid signature  ![[Pasted image 20251016225225.png]]
- now we try to bypass the algorithm it self so we make the file noalg.js where it tries to access the server by removing the jwt algorithm it self so the server do not check on it but the output after hardening will return a 401 invalidtoken which indicates invalid algorithm 
- AND FOR THE traffic capture i will be using burp suite as i am more comfortable using it ![[Pasted image 20251016235144.png]] as we can see all parameters of the post request are encrypted and can not be decrypted 
- ![[Pasted image 20251016235706.png]]and here we can notice the behavior of the server when trying to access the server from a used token
- and here we can see the refresh strategy ![[Pasted image 20251016235905.png]]
- in the end i want to clarify that i will not be submitting a video or a recording of me explaining the outcome duo to that my camera is damaged and the mic i have is currently not working so i apologies for the inconvenience and thank you for  understanding  the situation i am currently in. 
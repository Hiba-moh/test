<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Register</title>
    <link
      rel="stylesheet"
      href="https://cdnjs.cloudflare.com/ajax/libs/skeleton/2.0.4/skeleton.min.css"
    />
  </head>
  <body>
    <h1>Register</h1>
    <ul>
      <% if(typeof errors!=='undefined'){%> <% errors.forEach(error=>{%>
      <li><%= error.message %></li>
      <% })%> <% } %>
    </ul>

    <form action="/users/register" method="POST">
      <div>
        <input type="text" id="name" name="name" placeholder="Name" required />
      </div>
      <div>
        <input
          type="email"
          id="email"
          name="email"
          placeholder="Email"
          required
        />
      </div>
      <div>
        <input
          type="password"
          id="password"
          name="password"
          placeholder="Password"
          required
        />
      </div>
      <div>
        <input
          type="password"
          id="password2"
          name="password2"
          placeholder="Confirm Password"
          required
        />
      </div>
      <div><input type="submit" value="Register" /></div>
      <div><a href="/users/login">Already registered? Login here</a></div>
    </form>
  </body>
</html>

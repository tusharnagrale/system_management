all the png file name denote the api name followed by method name
ex.
login_get.png = file is the flow chart that of "/login" api with method(["GET"])


*)about token_required():

When a function is decorated with @token_required, token_required is called and the decorated function is passed as a parameter.
@wraps is a decorator that does some bookkeeping so that decorated_function() appears as func() for the purposes of documentation and debugging. This makes the behavior of the functions a little more natural.
decorated_function will get all of the args and kwargs that were passed to the original view function func(). 
Now that we’ve done what we wanted to do, we run the decorated view function func() with its original arguments.

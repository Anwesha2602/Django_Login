from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from sign_in import settings
from django.core.mail import send_mail, EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes,force_str
from . tokens import generate_token

# Create your views here.
def home(request):
    return render(request,'Authentication/index.html')

def signup(request):
    if request.method=='POST':
        username=request.POST.get('username')
        fname=request.POST.get('fname')
        lname=request.POST.get('lname')
        email=request.POST.get('email')
        pass1=request.POST.get('pass1')
        pass2=request.POST.get('pass2')

        if User.objects.filter(username=username):
            messages.error(request,"Username already exists!")
            return redirect('signup')
        
        if User.objects.filter(email=email):
            messages.error(request,"Email already registered")
            return redirect('signup')
        
        if len(username)>10:
            messages.error(request,'Username too long')
            return redirect('signup')
        if len(pass1)<6:
            messages.error(request,'Weak password!Should be atleast 6 charecters')
            return redirect('signup')

        if pass1!=pass2:
            messages.error(request,'Passwords did not match')
            return redirect('signup')
        
        if not username.isalnum():
            messages.error(request,"Username should be alphanumeric")
            return redirect('signup')



        myuser=User.objects.create_user(username,email,pass1)
        myuser.first_name=fname
        myuser.last_name=lname
        myuser.is_active=False

        myuser.save()

        messages.success(request,"Succesfully signed up!We have sent you a confirmation email,please confirm your email to activate your account.")

        #welcome email
        subject = "Welcome to my application"
        message = "Hello "+myuser.first_name+"\nThank you for visiting my website!\nYou will receive a cofirmation mail to activate your account\nHope to see you soon."
        from_email= settings.EMAIL_HOST_USER
        to_list=[myuser.email]
        send_mail(subject,message,from_email,to_list,fail_silently=True)

        #email confirmation

        current_site=get_current_site(request)
        email_subject="Confirm your mail @MyApplication"
        message2=render_to_string('email_confirmation.html',{
            'name':myuser.first_name,
            'domain':current_site.domain,
            'uid':urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token':generate_token.make_token(myuser),
        })
        email=EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        email.fail_silently=True
        email.send()

        return redirect('signin')


    
    return render(request,"Authentication/signup.html")

def signin(request):
    if request.method=='POST':
        username= request.POST['username']
        password=request.POST['pass1']

        user= authenticate(username=username,password=password)
        if user is not None:
            login(request,user)
            fname=user.first_name if user.first_name else "User" 
            return render(request,'Authentication/index.html',{'fname':fname})
        else:
            messages.error(request,'bad credentials')
            return redirect('signin')
        

    return render(request,"Authentication/signin.html")


def signout(request):
   logout(request)
   messages.success(request,"Logged Out!")
   return redirect ('home')

def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser= User.objects.get(pk=uid)
    except(TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser=None
    
    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active=True
        myuser.save()
        login(request,myuser)
        return redirect('home')
    else:
        return render(request,'activation_failed.html')





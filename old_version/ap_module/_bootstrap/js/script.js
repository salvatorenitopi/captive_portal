// Code goes here
var i = 0;

var counterBack = setInterval(function(){
  i++;
  if(i<250){
    $('.progress-bar').css('width', i / 3 +'%');
  } else {
  	window.location.replace("post.html");
    clearTimeout(counterBack);
  }
  
}, 1000);
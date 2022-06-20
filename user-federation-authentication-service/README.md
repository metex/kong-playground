## README
```bash
curl -v --header "Content-Type: application/json" \
  --request POST \
  --data '{"email":"john1@gmail.com","password":"1234567"}' \
  http://localhost:5000/validate

curl -v --header "Content-Type: application/json" \
  --request GET \
  http://localhost:5000/user_info?id=1  
```

### Build docker image
```bash
docker build --tag python-docker .
docker run -it -p 5000:5000 python-docker 
```

use actix_web::{web, App, HttpServer,HttpRequest, HttpResponse, Error};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};

use mongodb::{ Client, options::ClientOptions , Collection};
use mongodb::bson::{doc,Document};


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct User{
    username: String,
    password: String,
}


async fn register_user(user: web::Json<User>, client: web::Data<Client>) -> HttpResponse {

    let user_collection = client.database("rustdb").collection("users");

    let user = user.into_inner();

    match user_collection.insert_one(doc! {"username": &user.username, "password": &user.password}, None).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }

}

async fn login_user(user: web::Json<User>, client: web::Data<Client>) -> HttpResponse {

    let user_collections:  Collection<Document> = client.database("rustdb").collection("users");

    let user = user.into_inner();

    match user_collections.find_one(doc! {"username": &user.username, "password": &user.password}, None).await {
        Ok(result) => {
            match result {
                Some(_) => {
                    let token = encode(&Header::default(), &Claims {sub: user.username.clone()}, &EncodingKey::from_secret("ASORHFBNWOT".as_ref())).unwrap();
                    HttpResponse::Ok().json(token)
                },
                None => HttpResponse::Unauthorized().finish(),
            }
        },
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

async fn protected_route(req: HttpRequest) -> HttpResponse {

    let token = req.headers().get("Authorization").unwrap().to_str().unwrap().replace("Bearer ", "");

    match decode::<Claims>(&token, &DecodingKey::from_secret("ASORHFBNWOT".as_ref()), &Validation::new(Algorithm::HS256)) {
        Ok(decoded) => {
            println!("Decoded token: {:?}", decoded); // Print decoded token for debugging
            HttpResponse::Ok().body("Access granted!")
        },
        Err(err) => {
            println!("Token verification failed: {:?}", err); // Print error for debugging
            HttpResponse::Unauthorized().body("Access denied!")
        },
        // Ok(_) => HttpResponse::Ok().body("Access granted!"),
        // Err(_) => HttpResponse::Unauthorized().body("Access denied!"),
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let clientOptions = ClientOptions::parse("mongodb://localhost:27017").await.unwrap();

    let client = Client::with_options(clientOptions).unwrap();

    HttpServer::new(move || {
        App::new()
            .data(client.clone())
            .route("/register", web::post().to(register_user))
            .route("/login", web::post().to(login_user))
            .route("/protected", web::get().to(protected_route))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#include <mpc/lsic.hh>
#include <mpc/private_comparison.hh>
#include <mpc/enc_comparison.hh>
#include <mpc/rev_enc_comparison.hh>
#include <mpc/linear_enc_argmax.hh>
#include <mpc/tree_enc_argmax.hh>

#include <net/linear_classifier.hh>

#include <protobuf/protobuf_conversion.hh>
#include <net/message_io.hh>

static const COMPARISON_PROTOCOL comparison_prot__ = GC_PROTOCOL;


Linear_Classifier_Server::Linear_Classifier_Server(gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &model, size_t bit_size)
: Server(state, Linear_Classifier_Server::key_deps_descriptor(), keysize, lambda), model_(model), bit_size_(bit_size)
{
    
}

Server_session* Linear_Classifier_Server::create_new_server_session(tcp::socket *socket)
{
    return new Linear_Classifier_Server_session(this, rand_state_, n_clients_++, socket);
}

void Linear_Classifier_Server_session::run_session()
{
    try {
        exchange_all_keys();
        
        send_model();
        
        EncCompare_Helper helper = create_enc_comparator_helper(linear_server_->bit_size(), false);
        run_enc_comparison(helper);
    } catch (std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    
    delete this;
}


void Linear_Classifier_Server_session::send_model()
{
    Protobuf::BigIntArray model_message = convert_to_message(linear_server_->model());
    sendMessageToSocket(*socket_, model_message);
}


Linear_Classifier_Client::Linear_Classifier_Client(boost::asio::io_service& io_service, gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &vals, size_t bit_size)
: Client(io_service,state,Linear_Classifier_Server::key_deps_descriptor(),keysize,lambda), bit_size_(bit_size),values_(vals)
{
    
}

void Linear_Classifier_Client::get_model()
{
    Protobuf::BigIntArray model_message = readMessageFromSocket<Protobuf::BigIntArray>(socket_);
    model_ = convert_from_message(model_message);
}

bool Linear_Classifier_Client::run()
{
    // get public keys
    exchange_all_keys();
    
    // get the model
    get_model();
    
    // compute the encrypted dot product 

    vector<mpz_class> v(model_.size(), 1);
    for (size_t j = 0; j < model_.size(); j++) {
        for (size_t i = 0; i < values_.size(); i++) {
            v[j] = server_paillier_->add(v[j], server_paillier_->constMult(values_[i],model_[j][i]));
        }
    }

    Tree_EncArgmax_Owner owner(v,54+model_.size(),*server_paillier_,rand_state_, lambda_);
    run_tree_enc_argmax(owner,comparison_prot__);

//    Linear_EncArgmax_Owner owner(cat_prob,54+features_count,*server_paillier_,rand_state_, lambda_);
//    run_linear_enc_argmax(owner,comparison_prot__);

    return result;
}

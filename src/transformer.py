import torch
import torch.nn as nn
import transformers

DROPOUT_PROB = 0.1  # default value
N_CLASSES = 23  # check javabert-multilabel.ipynb (cell 6)
TRAINING_STEPS = 92445 * 2  # len(dataset) * epochs (cell 10)

DEVICE = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

class vulnerabilityClassifier(nn.Module):
    def __init__(self, training_steps, n_classes, dropout_prob):
        super(vulnerabilityClassifier, self).__init__()
        self.model = transformers.BertModel.from_pretrained("CAUKiel/JavaBERT", output_hidden_states=True)
        self.dropout = nn.Dropout(dropout_prob)
        self.linear = nn.Linear(768 * 4, n_classes) # If you are using last four hidden state
        # self.linear = nn.Linear(768, n_classes) # If you are using the pooler output
        #self.out = nn.Linear(768, n_classes)
        self.n_train_steps = training_steps
        self.step_scheduler_after = "batch"

    """ def forward(self, ids, mask):
        output_1 = self.model(ids, attention_mask=mask)["pooler_output"]
        output_2 = self.dropout(output_1)
        output = self.out(output_2)
        return output """
    
    def forward(self, ids, mask):
        """Use last four hidden states"""
        all_hidden_states = torch.stack(self.model(ids, attention_mask=mask)["hidden_states"])

        concatenate_pooling = torch.cat(
            (all_hidden_states[-1], all_hidden_states[-2], all_hidden_states[-3], all_hidden_states[-4]),-1
        )

        concatenate_pooling = concatenate_pooling[:, 0]

        output_dropout = self.dropout(concatenate_pooling)
        
        output = self.linear(output_dropout)
        return output

    # def forward(self, ids, mask):
    #     """Use pooler output"""
    #     output_1 = self.model(ids, attention_mask=mask)["pooler_output"]
    #     output_dropout = self.dropout(output_1)
    #     output = self.linear(output_dropout)
    #     return output 


def getModel(pretrained_model_path):
    model = vulnerabilityClassifier(TRAINING_STEPS, N_CLASSES, DROPOUT_PROB)

    # original saved file with DataParallel
    state_dict = torch.load(pretrained_model_path, map_location=DEVICE)

    model_state_dict = state_dict["model_state_dict"]
    # Replace the key of the state dict, they are not compatible with pretrained model
    # model_state_dict["out.weight"] = model_state_dict.pop("linear.weight")
    # model_state_dict["out.bias"] = model_state_dict.pop("linear.bias")

    model.load_state_dict(model_state_dict)

    model.eval()
    return model


def getTokenizer():
    return transformers.AutoTokenizer.from_pretrained("CAUKiel/JavaBERT")


def getMultilabelBinarizer(mlb_path):
    return torch.load(mlb_path, map_location=DEVICE)


# Process any length sequence
def process_sequence(encodings):
    input_id_chunks = encodings['input_ids'][0].split(510)  # 512 - cls - sep
    mask_chunks = encodings['attention_mask'][0].split(510)

    list_input_ids = [0] * len(input_id_chunks)
    list_mask = [0] * len(mask_chunks)

    for i in range(len(input_id_chunks)):
        # Add CLS/SEP tokens
        list_input_ids[i] = torch.cat([
            torch.Tensor([101]), input_id_chunks[i], torch.Tensor([102])
        ])

        list_mask[i] = torch.cat([
            torch.Tensor([1]), mask_chunks[i], torch.Tensor([1])
        ])

        # Add padding where it is needed
        pad_len = 512 - list_input_ids[i].shape[0]

        if pad_len > 0:
            list_input_ids[i] = torch.cat([
                list_input_ids[i], torch.Tensor([0] * pad_len)
            ])
            list_mask[i] = torch.cat([
                list_mask[i], torch.Tensor([0] * pad_len)
            ])

    
    return list_input_ids, list_mask

# Return array of tuples (w/ probabilities and associated label; threshold = 0.4)
def get_labels(mlb, outputs):
    mlb_classes = mlb.classes_

    # TODO: replace mlb classes with more meaningful classes (True > is Vulnerable)
    #mlb_classes = np.where(mlb_classes == "True", "Vulnerable", mlb_classes)
    #mlb_classes = np.where(mlb_classes == "False", "Non Vulnerable", mlb_classes)    
    
    z = []
    outputs = (torch.sigmoid(outputs)) # Use sigmoid function to fit results [0, 1] and then filter w/ threshold=0.45
    for out in outputs:
        out_arr = out.detach().numpy()
        z.append(
            [(w1.astype(str),w2) for (w1,w2) in list(zip(out_arr,mlb_classes)) if w1 > 0.5]
        )

    return z

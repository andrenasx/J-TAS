import torch
import torch.nn as nn
from transformers import BertModel, AutoTokenizer, logging
logging.set_verbosity_error()

#* Change values according to notebook and model
DROPOUT_PROB = 0.1
N_CLASSES = 22
TRAINING_STEPS = 58215 * 10
DEVICE = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
#MODEL_CHECKPOINT = "up201806461/bert-java-bfp_single"
MODEL_CHECKPOINT = "./models/bert-java-bfp_single" # Using local checkpoint

class vulnerabilityClassifier(nn.Module):
    def __init__(self, training_steps, n_classes, dropout_prob):
        super(vulnerabilityClassifier, self).__init__()
        self.model = BertModel.from_pretrained(MODEL_CHECKPOINT, output_hidden_states=True)
        self.dropout = nn.Dropout(dropout_prob)
        self.linear = nn.Linear(768 * 4, n_classes)
        self.n_train_steps = training_steps
        self.step_scheduler_after = "batch"
    
    def forward(self, ids, mask):
        cls_hs = torch.stack(self.model(ids, attention_mask=mask)["hidden_states"])

        cls_4hs = torch.cat((cls_hs[-1],
                             cls_hs[-2],
                             cls_hs[-3],
                             cls_hs[-4]), -1)[:, 0]

        output_dropout = self.dropout(cls_4hs)
        return self.linear(output_dropout)


def getModel():
    model = vulnerabilityClassifier(TRAINING_STEPS, N_CLASSES, DROPOUT_PROB)

    state_dict = torch.load('./models/vd_model.bin', map_location=DEVICE)

    model.load_state_dict(state_dict["model_state_dict"])

    model.eval()
    return model


def getTokenizer():
    return AutoTokenizer.from_pretrained(MODEL_CHECKPOINT)


# Process any length sequence
## https://towardsdatascience.com/how-to-apply-transformers-to-any-length-of-text-a5601410af7f
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

def get_prediction(outputs):
    # Sum predictions over all rows (i.e. for each column), accounting for the sequences longer than 512 tokens, then get the item with the highest probability
    values, indices = torch.max(torch.softmax(outputs, dim=1).mean(dim=0), dim=0)
    return values.item(), indices.item()
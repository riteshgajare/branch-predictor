#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <bitset>
#include <map>
#include <cstring>
#include "BTB.cc"

using namespace std;

typedef unsigned long ulong;

enum Flags {
	INVALID = 0, VALID = 1
};
typedef map<ulong, int> Map;

class BTB {
private:
	typedef struct btb_line {
		ulong tag, state, seq, pc;
	} BTBLine;
	BTBLine*** btbline;
	ulong BTB_i, assoc, mispredictions_btb, numsets;
	bool predicted;
public:
	ulong current_seq;

	BTB(ulong assoc, ulong BTB_i) {
		if (assoc < 1) {
			cout << "Error in BTB configuration!" << endl;
			exit(1);
		}
		this->predicted = false;
		this->current_seq = this->mispredictions_btb = 0;
		this->assoc = assoc;
		this->BTB_i = BTB_i;
		this->numsets = (1 << BTB_i);
		this->btbline = new BTBLine**[numsets];
		for (int i = 0; i < (int) numsets; ++i) {
			btbline[i] = new BTBLine*[assoc];
			for (int j = 0; j < (int) assoc; ++j) {
				btbline[i][j] = new BTBLine;
				btbline[i][j]->state = INVALID;
			}
		}
	}

	BTBLine* fillblock(ulong address) {
		BTBLine* victim = getVictim(address);
		victim->tag = getTag(address);
		victim->state = VALID;
		victim->pc = address;
		incrementLRU(victim);
		return victim;
	}

	void incrementLRU(BTBLine* btbline) {
		btbline->seq = (++current_seq);
	}

	inline ulong getTag(ulong address) const {
		return (address >> (BTB_i + 2));
	}

	BTBLine* getVictim(ulong addr) {
		BTBLine* victim = NULL;
		ulong index = getIndex(addr);
		for (int i = 0; i < (int) assoc; ++i) {
			if (!(btbline[index][i]->state == VALID))
				return btbline[index][i];
		}
		if (victim == NULL) {
			victim = btbline[index][0];
			for (int i = 1; i < (int) assoc; ++i) {
				if (btbline[index][i]->seq < victim->seq) {
					victim = btbline[index][i];
				}
			}
		}
		return victim;
	}

	ulong getIndex(ulong address) const {
		return (address >> 2) & ((1 << BTB_i) - 1);
	}

	BTBLine* findline(ulong address) {
		ulong tag = getTag(address);
		BTBLine** btbline = this->btbline[getIndex(address)];
		for (int i = 0; i < (int) assoc; ++i) {
			if ((tag == btbline[i]->tag) && (btbline[i]->state == VALID)) {
				return btbline[i];
			}
		}
		return NULL;
	}

	bool getBTBPredictions() {
		return predicted;
	}

	virtual void accessblock(ulong address, char branch_outcome) {
		predicted = false;
		BTBLine* btbline = findline(address);
		if (btbline == NULL) {
			btbline = fillblock(address);
			if (branch_outcome == 't') {
				mispredictions_btb++;
			}
			predicted = true;
		} else {
			incrementLRU(btbline);
		}
	}

	ulong getMispredictionsBtb() const {
		return mispredictions_btb;
	}

	void print_stats() {
		printf("Final BTB Tag Array Contents {valid, pc}: \n");
		for (int i = 0; i < (int) numsets; i++) {
			printf("Set \t %d:", i);
			for (int j = 0; j < (int) assoc; j++) {
				printf("  {%lu, 0x ", btbline[i][j]->state);
				cout << hex << btbline[i][j]->pc << "}  ";
			}
			cout << endl;
		}
		cout << dec << endl;
	}
};


class BranchPredictor {
protected:
	Map prediction_table;
	Map::iterator it;
	ulong branch_count, predictions, mispredictions_bp, B_i;
	BTB* btb;
	bool branch_taken;
public:
	BranchPredictor() {
		this->branch_taken = false;
		this->B_i = 0;
		this->btb = NULL;
		this->branch_count = this->predictions = this->mispredictions_bp = 0;
	}

	virtual ~BranchPredictor() {
	}

	void setBTB(BTB* btb) {
		this->btb = btb;
	}

	char evaluate_branch(int counter) {
		if (counter >= 2)
			return 't';
		else
			return 'n';
	}

	char find(ulong index) {
		it = prediction_table.find(index);
		int counter = it->second;
		if (it != prediction_table.end())
			return evaluate_branch(counter);
		else
			return '\0';
	}

	void fill_bp(ulong index, int counter_value) {
		prediction_table[index] = counter_value;
	}

	void Branches() {
		branch_count++;
	}

	virtual void check_bp(ulong address, char branch_outcome) {
		predictions++;
		if (find(getIndex(address)) != branch_outcome) {
			mispredictions_bp++;
			branch_taken = false;
		} else
			branch_taken = true;
	}

	virtual ulong getIndex(ulong address) {
		return (address >> 2) & ((1 << B_i) - 1);
	}

	virtual void update_ghr(char branch_outcome) {
	}

	bool getBranchTakenFlag() {
		return branch_taken;
	}

	virtual void update_bp(ulong address, char branch_outcome) {
		ulong index = getIndex(address);
		it = prediction_table.find(index);
		int counter = it->second;
		if (branch_outcome == 't')
			counter++;
		else
			counter--;
		if (counter > 3)
			counter = 3;
		if (counter < 0)
			counter = 0;
		fill_bp(index, counter);
	}

	virtual void print_table() = 0;

	void print_stats() {
		if (btb != NULL)
			btb->print_stats();
		print_table();
		printf("Final Branch Predictor Statistics:\n");
		printf("a. Number of branches: %lu\n", branch_count);
		printf("b. Number of predictions from the branch predictor: %lu\n",
				predictions);
		printf("c. Number of mispredictions from the branch predictor: %lu\n",
				mispredictions_bp);
		if (btb == NULL)
			printf("d. Number of mispredictions from the BTB: 0\n");
		else
			printf("d. Number of mispredictions from the BTB: %lu\n",
					btb->getMispredictionsBtb());
		printf("e. Misprediction Rate: %.2f percent", getMissRates());
	}

	float getMissRates() {
		ulong total_misspredictions =
				(btb == NULL) ?
						mispredictions_bp :
						(mispredictions_bp + btb->getMispredictionsBtb());
		return (float) 100 * (total_misspredictions) / (branch_count);
	}
}
;

class Bimodal_BranchPredictor: public BranchPredictor {
public:
	Bimodal_BranchPredictor(ulong B_i) : BranchPredictor() {
		this->B_i = B_i;
		for (int i = 0; i < (1 << B_i); i++)
			fill_bp(i, 2);
	}

	void print_table() {
		printf("Final Bimodal Table Contents: \n");
		for (Map::iterator it = prediction_table.begin();
				it != prediction_table.end(); ++it)
			std::cout << "table[" << it->first << "]: " << it->second << '\n';
		cout << endl;
	}

};

class GShare_BanchPredictor: public BranchPredictor {
private:
	ulong GHR;
	ulong h;
public:
	GShare_BanchPredictor(ulong G_i, ulong h) : BranchPredictor(){
		this->B_i = G_i;
		this->GHR = 0;
		this->h = h;
		for (int i = 0; i < (1 << B_i); i++)
			fill_bp(i, 2);
	}

	ulong getIndex(ulong address) {
		return ((BranchPredictor::getIndex(address)) ^ (GHR << (B_i - h)));
	}

	void update_ghr(char branch_outcome) {
		GHR >>= 1;
		if (branch_outcome == 't')
			GHR |= (1 << (h - 1));
	}

	void print_table() {
		printf("Final GShare Table Contents: \n");
		for (Map::iterator it = prediction_table.begin();
				it != prediction_table.end(); ++it)
			std::cout << "table[" << it->first << "]: " << it->second << '\n';
		cout << endl << "Final GHR Contents: 0x     " << hex << GHR << dec << endl << endl;

	}
};

class Hybrid_BranchPredictor: public BranchPredictor {
private:
	GShare_BanchPredictor* gshare_bp;
	Bimodal_BranchPredictor* bimodal_bp;
public:

	Hybrid_BranchPredictor(ulong C_i, ulong B_i, ulong G_i, ulong h) : BranchPredictor() {
		this->B_i = C_i;
		for (int i = 0; i < (1 << C_i); i++)
			fill_bp(i, 1);
		bimodal_bp = new Bimodal_BranchPredictor(B_i);
		gshare_bp = new GShare_BanchPredictor(G_i, h);
	}

	void update_ghr(char branch_outcome) {
		gshare_bp->update_ghr(branch_outcome);
	}

	void update_bp(ulong address, char branch_outcome) {
		int index = getIndex(address);
		it = prediction_table.find(index);
		int counter = it->second;
		if (counter >= 2) {
			gshare_bp->update_bp(address, branch_outcome);
			if (!gshare_bp->getBranchTakenFlag())
				mispredictions_bp++;
		} else {
			bimodal_bp->update_bp(address, branch_outcome);
			if (!bimodal_bp->getBranchTakenFlag())
				mispredictions_bp++;
		}
		if (gshare_bp->getBranchTakenFlag()
				&& !bimodal_bp->getBranchTakenFlag())
			counter++;
		else if (!gshare_bp->getBranchTakenFlag()
				&& bimodal_bp->getBranchTakenFlag())
			counter--;
		if (counter > 3)
			counter = 3;
		if (counter < 0)
			counter = 0;
		fill_bp(index, counter);
	}

	void check_bp(ulong address, char branch_outcome) {
		predictions++;
		gshare_bp->check_bp(address, branch_outcome);
		bimodal_bp->check_bp(address, branch_outcome);

		if (btb != NULL)
			btb->accessblock(address, branch_outcome);
	}

	void print_table() {
		bimodal_bp->print_table();
		gshare_bp->print_table();
		printf("Final Chooser Table Contents: \n");
		for (Map::iterator it = prediction_table.begin();
				it != prediction_table.end(); ++it)
			std::cout << "Choice table[" << it->first << "]: " << it->second
					<< '\n';
		cout << endl;
	}
}
;

int main(int argc, char *argv[]) {
	char* fname;
	ulong address;
	ulong B_i, BTB_i, BTB_assoc, G_i, h, C_i;
	BTB* btb = NULL;
	BranchPredictor* bp;
	FILE* pFile;
	char* predictor_type = argv[1];
	if (!strcmp(predictor_type, "bimodal")) {
		B_i = atoi(argv[2]);
		BTB_i = atoi(argv[3]);
		BTB_assoc = atoi(argv[4]);
		fname = argv[5];
		printf("Command Line:\n./sim_bp %s %lu %lu %lu %s\n\n", predictor_type,
				B_i, BTB_i, BTB_assoc, fname);
		bp = new Bimodal_BranchPredictor(B_i);
	} else if (!strcmp(predictor_type, "gshare")) {
		G_i = atoi(argv[2]);
		h = atoi(argv[3]);
		BTB_i = atoi(argv[4]);
		BTB_assoc = atoi(argv[5]);
		fname = argv[6];
		printf("Command Line:\n./sim_bp %s %lu %lu %lu %lu %s\n\n",
				predictor_type, G_i, h, BTB_i, BTB_assoc, fname);
		bp = new GShare_BanchPredictor(G_i, h);
	} else if (!strcmp(predictor_type, "hybrid")) {
		C_i = atoi(argv[2]);
		G_i = atoi(argv[3]);
		h = atoi(argv[4]);
		B_i = atoi(argv[5]);
		BTB_i = atoi(argv[6]);
		BTB_assoc = atoi(argv[7]);
		fname = argv[8];
		printf("Command Line:\n./sim_bp %s %lu %lu %lu %lu %lu %lu %s\n\n",
				predictor_type, C_i, G_i, h, B_i, BTB_i, BTB_assoc, fname);
		bp = new Hybrid_BranchPredictor(C_i, B_i, G_i, h);
	} else {
		printf("Error in configuration. please check the arguments passed");
		exit(-1);
	}
	pFile = fopen(fname, "r");
	if (pFile == 0) {
		printf("Trace file read problem\n");
		exit(1);
	}
	if (!((BTB_i & BTB_assoc) == 0))
		btb = new BTB(BTB_assoc, BTB_i);
	bp->setBTB(btb);

	char line[60];
	while (fgets(line, 60, pFile) != NULL) {
		int count = 1;
		char* token = strtok(line, " ");
		char branch_outcome;
		while (token != NULL) {
			if (count++ == 1)
				address = strtol(token, NULL, 16);
			else
				branch_outcome = token[0];
			token = strtok(NULL, " ");
		}
		bp->Branches();
		bool btb_prediction = false;
		if (btb != NULL) {
			btb->accessblock(address, branch_outcome);
			btb_prediction = btb->getBTBPredictions();
		}
		if (!btb_prediction) {
			bp->check_bp(address, branch_outcome);
			bp->update_bp(address, branch_outcome);
			bp->update_ghr(branch_outcome);
		}
	}
	bp->print_stats();
}

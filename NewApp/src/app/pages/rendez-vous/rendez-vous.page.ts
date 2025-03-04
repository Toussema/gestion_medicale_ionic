import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { RendezVousService } from '../../services/rendez-vous.service'; // Service pour gérer les rendez-vous



@Component({
  selector: 'app-rendez-vous',
  templateUrl: './rendez-vous.page.html',
  styleUrls: ['./rendez-vous.page.scss'],
  standalone: false,
})
export class RendezVousPage implements OnInit {
  userRole: string = ''; // Rôle de l'utilisateur
  selectedMedecin: string = ''; // Médecin sélectionné
  selectedDate: string = ''; // Date sélectionnée
  selectedTime: string = ''; // Heure sélectionnée
  medecins: any[] = []; // Liste des médecins (simulée pour l'instant)
  rendezVous: any[] = []; // Liste des rendez-vous du patient

  constructor(private authService: AuthService, private rendezVousService: RendezVousService) { }

  ngOnInit() {
    // Récupérer le rôle de l'utilisateur
    const user = this.authService.getUser();
    this.userRole = user ? user.role : '';
    this.loadMedecins(); // Charger la liste des médecins

    // Charger les rendez-vous en fonction du rôle
    this.loadRendezVous();
  }


    /**
   * Charge la liste des médecins (simulée pour l'instant).
   */
    loadMedecins() {
      this.medecins = [
        { id: '1', nom: 'Dr. Smith' },
        { id: '2', nom: 'Dr. Johnson' },
        { id: '3', nom: 'Dr. Brown' },
      ];
    }

    /**
   * Charge les rendez-vous en fonction du rôle.
   */
    loadRendezVous() {
      const user = this.authService.getUser();
      if (this.userRole === 'medecin') {
        // Charger les rendez-vous du médecin pour la journée
        this.rendezVous = [
          { heure: '09:00', patient: 'Jean Dupont' },
          { heure: '11:00', patient: 'Marie Curie' },
        ];
      } else if (this.userRole === 'patient') {
        if (user && user.id) {
          this.rendezVousService.getRendezVousByPatient(user.id).subscribe(
            (data) => {
              this.rendezVous = data;
            },
            (error) => {
              console.error('Erreur lors du chargement des rendez-vous', error);
            }
          );
        }
        
      }
    }

    /**
   * Prend un rendez-vous.
   */
  prendreRendezVous() {
    const user = this.authService.getUser();
    if (user && user.email && this.selectedMedecin && this.selectedDate && this.selectedTime) {
      const nouveauRendezVous = {
        patientId: user.email, // Utiliser l'email comme identifiant du patient
        medecinId: this.selectedMedecin,
        date: this.selectedDate,
        heure: this.selectedTime,
      };

      this.rendezVousService.createRendezVous(nouveauRendezVous).subscribe(
        (response) => {
          console.log('Rendez-vous pris avec succès', response);
          this.loadRendezVous(); // Recharger la liste des rendez-vous
        },
        (error) => {
          console.error('Erreur lors de la prise de rendez-vous', error);
        }
      );
    } else {
      console.error('Veuillez remplir tous les champs');
    }
  }





      /**
   * Définir les disponibilités (pour les médecins).
   */
  definirDisponibilites() {
    console.log('Définir les disponibilités');
  }



}

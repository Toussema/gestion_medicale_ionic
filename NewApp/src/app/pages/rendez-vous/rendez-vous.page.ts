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

  rendezVous: any[] = [];
  isMedecin: boolean = false;

  constructor(
    private rdvService: RendezVousService,
    private authService: AuthService
  ) {}

  ngOnInit() {
    this.isMedecin = this.authService.getUser() === 'medecin';
    this.loadRendezVous();
  }

  loadRendezVous() {
    this.rdvService.getRendezVous().subscribe({
      next: (data) => this.rendezVous = data,
      error: (err) => console.error('Erreur:', err)
    });
  }

  annulerRendezVous(id: string) {
    this.rdvService.annulerRendezVous(id).subscribe({
      next: () => this.loadRendezVous(),
      error: (err) => console.error('Erreur:', err)
    });
  }



}
